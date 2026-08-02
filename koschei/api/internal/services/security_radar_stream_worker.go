package services

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	SecurityRadarStreamProvider = "solana_wss"
	SecurityRadarStreamModeLogs = "logs_subscribe"
)

type SecurityRadarStreamEventRecord struct {
	Provider        string
	StreamMode      string
	Network         string
	ModuleID        string
	EventType       string
	Target          string
	TargetType      string
	Signature       string
	Slot            int64
	ProgramID       string
	EvidenceQuality string
	Decoded         map[string]any
	RawEvent        map[string]any
}

type SecurityRadarStreamWorker struct {
	Store      *SecurityRadarStore
	WSSURL     string
	RPCURL     string
	Network    string
	BufferSize int
	Queue      chan SecurityRadarStreamEventRecord
}

func StartSecurityRadarStreamIfEnabled(ctx context.Context, db *sql.DB) func() {
	if db == nil || !securityRadarStreamEnabled() {
		return func() {}
	}
	wssURL := resolveSecurityRadarWSSURL()
	if wssURL == "" {
		log.Printf("security radar SBX-1 stream not started: no WSS URL could be resolved from SOLANA_WSS_URL, provider WSS env, SOLANA_RPC_URL, or ALCHEMY_API_KEY")
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	worker := NewSecurityRadarStreamWorker(NewSecurityRadarStore(db), wssURL, resolveSecurityRadarRPCURL())
	go worker.Start(ctx)
	return cancel
}

func securityRadarStreamEnabled() bool {
	return envBool("RADAR_STREAM_ENABLED") || envBool("KOSCHEI_AUTO_RADAR_ENABLED") || strings.EqualFold(strings.TrimSpace(os.Getenv("KOSCHEI_SOLANA_WATCH_MODE")), "stream")
}

func resolveSecurityRadarWSSURL() string {
	if v := firstSecurityRadarEnv("SOLANA_WSS_URL", "ALCHEMY_SOLANA_WSS_URL", "HELIUS_SOLANA_WSS_URL", "QUICKNODE_SOLANA_WSS_URL"); v != "" {
		return v
	}
	if rpc := strings.TrimSpace(os.Getenv("SOLANA_RPC_URL")); rpc != "" {
		if strings.HasPrefix(rpc, "https://") {
			return "wss://" + strings.TrimPrefix(rpc, "https://")
		}
		if strings.HasPrefix(rpc, "http://") {
			return "ws://" + strings.TrimPrefix(rpc, "http://")
		}
	}
	if key := strings.TrimSpace(os.Getenv("ALCHEMY_API_KEY")); key != "" {
		return "wss://solana-mainnet.g.alchemy.com/v2/" + key
	}
	return ""
}

func resolveSecurityRadarRPCURL() string {
	if v := firstSecurityRadarEnv("SOLANA_RPC_URL", "ALCHEMY_SOLANA_RPC_URL", "HELIUS_SOLANA_RPC_URL", "QUICKNODE_SOLANA_RPC_URL"); v != "" {
		return v
	}
	if wss := strings.TrimSpace(os.Getenv("SOLANA_WSS_URL")); wss != "" {
		if strings.HasPrefix(wss, "wss://") {
			return "https://" + strings.TrimPrefix(wss, "wss://")
		}
		if strings.HasPrefix(wss, "ws://") {
			return "http://" + strings.TrimPrefix(wss, "ws://")
		}
	}
	if key := strings.TrimSpace(os.Getenv("ALCHEMY_API_KEY")); key != "" {
		return "https://solana-mainnet.g.alchemy.com/v2/" + key
	}
	return ""
}

func envBool(key string) bool {
	v := strings.TrimSpace(os.Getenv(key))
	return strings.EqualFold(v, "1") || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") || strings.EqualFold(v, "on")
}

func NewSecurityRadarStreamWorker(store *SecurityRadarStore, wssURL string, rpcURL string) *SecurityRadarStreamWorker {
	bufferSize := 5000
	if raw := strings.TrimSpace(os.Getenv("RADAR_EVENT_BUFFER_SIZE")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 100000 {
			bufferSize = n
		}
	}
	return &SecurityRadarStreamWorker{Store: store, WSSURL: strings.TrimSpace(wssURL), RPCURL: strings.TrimSpace(rpcURL), Network: firstRadarValue(os.Getenv("RADAR_STREAM_NETWORK"), "solana-mainnet"), BufferSize: bufferSize, Queue: make(chan SecurityRadarStreamEventRecord, bufferSize)}
}

func (w *SecurityRadarStreamWorker) Start(ctx context.Context) {
	if w == nil || w.Store == nil || w.Store.DB == nil || strings.TrimSpace(w.WSSURL) == "" {
		return
	}
	log.Printf("security radar SBX-1 WSS collector started provider=%s mode=%s network=%s enrichment_rpc=%t", SecurityRadarStreamProvider, SecurityRadarStreamModeLogs, w.Network, strings.TrimSpace(w.RPCURL) != "")
	go w.persistLoop(ctx)
	backoff := 3 * time.Second
	for {
		select {
		case <-ctx.Done():
			log.Printf("security radar SBX-1 WSS collector stopped")
			return
		default:
		}
		startedAt := time.Now()
		err := w.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(startedAt) >= 45*time.Second {
			backoff = 3 * time.Second
		}
		if isRadarRateLimitError(err) && backoff < 30*time.Second {
			backoff = 30 * time.Second
		}
		wait := radarReconnectWait(backoff)
		if err != nil {
			log.Printf("security radar SBX-1 WSS reconnect scheduled retry_in=%s err=%s", wait.Round(time.Second), safeProviderError(err))
		}
		if backoff < 2*time.Minute {
			backoff *= 2
			if backoff > 2*time.Minute {
				backoff = 2 * time.Minute
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func isRadarRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "429") || strings.Contains(message, "too many requests") || strings.Contains(message, "rate limit")
}

func radarReconnectWait(base time.Duration) time.Duration {
	if base <= 0 {
		base = 3 * time.Second
	}
	var sample [2]byte
	if _, err := rand.Read(sample[:]); err != nil {
		return base
	}
	jitterMax := base / 5
	if jitterMax <= 0 {
		return base
	}
	fraction := float64(binary.BigEndian.Uint16(sample[:])) / 65535.0
	return base + time.Duration(fraction*float64(jitterMax))
}

func (w *SecurityRadarStreamWorker) persistLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-w.Queue:
			w.persistEvent(ctx, event)
		}
	}
}

func (w *SecurityRadarStreamWorker) runOnce(ctx context.Context) error {
	conn, err := dialMinimalWebSocket(ctx, w.WSSURL)
	if err != nil {
		return err
	}
	defer conn.Close()
	for index, source := range arvisHeartbeatSources() {
		programID := strings.TrimSpace(source.ProgramID)
		if programID == "" {
			continue
		}
		subscription := map[string]any{"jsonrpc": "2.0", "id": index + 1, "method": "logsSubscribe", "params": []any{map[string]any{"mentions": []string{programID}}, map[string]any{"commitment": "confirmed"}}}
		if err := conn.WriteJSON(subscription); err != nil {
			return err
		}
	}
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ping.C:
			_ = conn.Ping()
		default:
		}
		payload, err := conn.ReadText(ctx)
		if err != nil {
			return err
		}
		event, ok := w.decodeLogsPayload(payload)
		if !ok {
			continue
		}
		select {
		case w.Queue <- event:
		default:
			log.Printf("security radar SBX-1 queue full; dropping signature=%s module=%s", event.Signature, event.ModuleID)
		}
	}
}

func (w *SecurityRadarStreamWorker) decodeLogsPayload(payload []byte) (SecurityRadarStreamEventRecord, bool) {
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return SecurityRadarStreamEventRecord{}, false
	}
	if !strings.Contains(anyString(raw["method"]), "logsNotification") {
		return SecurityRadarStreamEventRecord{}, false
	}
	params := asRadarMap(raw["params"])
	result := asRadarMap(params["result"])
	contextValue := asRadarMap(result["context"])
	value := asRadarMap(result["value"])
	logs := radarStringSlice(value["logs"])
	moduleID, eventType, programID := classifyRadarStreamText(strings.ToLower(strings.Join(logs, "\n")))
	if moduleID == "unknown" && !envBool("RADAR_STREAM_STORE_UNKNOWN") {
		return SecurityRadarStreamEventRecord{}, false
	}
	signature := anyString(value["signature"])
	target := signature
	return SecurityRadarStreamEventRecord{Provider: SecurityRadarStreamProvider, StreamMode: SecurityRadarStreamModeLogs, Network: w.Network, ModuleID: moduleID, EventType: eventType, Target: target, TargetType: targetTypeForRadarModule(moduleID), Signature: signature, Slot: radarInt64(contextValue["slot"]), ProgramID: programID, EvidenceQuality: evidenceQualityForRadarModule(moduleID), Decoded: map[string]any{"logs": logs, "err": value["err"], "subscription_method": "logsSubscribe"}, RawEvent: raw}, signature != "" || moduleID != "unknown"
}

func (w *SecurityRadarStreamWorker) persistEvent(ctx context.Context, event SecurityRadarStreamEventRecord) {
	event = w.enrichEventTarget(ctx, event)
	if _, err := w.Store.InsertStreamEvent(ctx, event); err != nil {
		log.Printf("security radar stream insert failed: %v", err)
		return
	}
	if event.ModuleID != ModulePumpSybilRadar && event.ModuleID != ModuleRaydiumPoolGuardian {
		return
	}
	if strings.TrimSpace(event.Target) == "" || strings.EqualFold(strings.TrimSpace(event.Target), strings.TrimSpace(event.Signature)) {
		return
	}
	analysis := AnalyzeArvisRadarsContext(ctx, SecurityRadarRequest{Target: event.Target, Network: event.Network, Mode: "live_stream:" + event.ModuleID})
	verdict := securityRadarModuleVerdict(analysis.Bundle, event.ModuleID)
	signals := mergeRadarMaps(verdict.Signals, map[string]any{"stream_event_type": event.EventType, "stream_mode": event.StreamMode, "stream_provider": event.Provider, "stream_signature": event.Signature, "stream_evidence_quality": event.EvidenceQuality})
	if !shouldPublishSBX1CustomerVerdict(event, verdict, signals) {
		log.Printf("security radar SBX-1 raw-only event retained signature=%s target=%s data_quality=%s evidence_status=%s", event.Signature, event.Target, anyString(signals["data_quality"]), anyString(signals["evidence_status"]))
		return
	}
	eventID, err := w.Store.InsertEvent(ctx, SecurityRadarEventRecord{ModuleID: verdict.ModuleID, Target: verdict.Target, TargetType: event.TargetType, Network: verdict.Network, Signature: firstRadarValue(event.Signature, verdict.Signature), SourceAddress: event.ProgramID, EventType: event.EventType, Slot: event.Slot, Signals: signals, RawSummary: event.Decoded, Source: "sbx1_stream"})
	if err != nil {
		log.Printf("security radar stream event-to-radar insert failed: %v", err)
		return
	}
	_, err = w.Store.InsertVerdict(ctx, SecurityRadarVerdictRecord{EventID: eventID, ModuleID: verdict.ModuleID, Target: verdict.Target, TargetType: event.TargetType, Network: verdict.Network, Grade: verdict.Grade, RiskIndex: verdict.RiskIndex, RiskLevel: verdict.RiskLevel, Verdict: verdict.Verdict, Recommendation: verdict.Recommendation, Evidence: append(verdict.Evidence, "SBX-1 WSS stream observed and enriched this target before manual dashboard analysis."), Signals: signals, RuleVersion: verdict.RuleVersion, Signed: verdict.Signed, Signature: verdict.Signature, Source: "sbx1_stream"})
	if err != nil {
		log.Printf("security radar stream verdict insert failed: %v", err)
	}
}

func shouldPublishSBX1CustomerVerdict(event SecurityRadarStreamEventRecord, verdict SecurityRadarVerdict, signals map[string]any) bool {
	if strings.TrimSpace(event.Target) == "" || strings.EqualFold(strings.TrimSpace(event.Target), strings.TrimSpace(event.Signature)) {
		return false
	}
	if !SecurityRadarVerdictHasVerifiedEvidence(verdict) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(event.EvidenceQuality), "transaction_enriched_mint") {
		return true
	}
	if ok, _ := signals["real_onchain_evidence"].(bool); !ok {
		return false
	}
	if !strings.EqualFold(anyString(signals["data_quality"]), "live_rpc_evidence") {
		return false
	}
	mint, _ := signals["is_token_mint"].(bool)
	return mint
}

func (w *SecurityRadarStreamWorker) enrichEventTarget(ctx context.Context, event SecurityRadarStreamEventRecord) SecurityRadarStreamEventRecord {
	if strings.TrimSpace(w.RPCURL) == "" || strings.TrimSpace(event.Signature) == "" {
		return event
	}
	needsEnrichment := strings.TrimSpace(event.Target) == "" || strings.EqualFold(strings.TrimSpace(event.Target), strings.TrimSpace(event.Signature))
	if !needsEnrichment {
		return event
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	tx, err := SolanaGetTransactionJSONParsed(ctx, w.RPCURL, event.Signature)
	if err != nil {
		event.Decoded["enrichment_error"] = compactRadarError("getTransaction", err)
		return event
	}
	mints := extractMintsFromTransactionMap(map[string]any(tx))
	if len(mints) > 0 {
		event.Target = mints[0]
		event.TargetType = "token"
		event.EvidenceQuality = "transaction_enriched_mint"
		event.Decoded["enriched_mint"] = mints[0]
		event.Decoded["enriched_mints"] = mints
	}
	return event
}

func (s *SecurityRadarStore) InsertStreamEvent(ctx context.Context, event SecurityRadarStreamEventRecord) (string, error) {
	if s == nil || s.DB == nil {
		return "", nil
	}
	decoded, _ := json.Marshal(nonNilMap(event.Decoded))
	rawEvent, _ := json.Marshal(nonNilMap(event.RawEvent))
	var id string
	err := s.DB.QueryRowContext(ctx, `
		INSERT INTO security_radar_stream_events (provider,stream_mode,network,module_id,event_type,target,target_type,signature,slot,program_id,evidence_quality,decoded,raw_event,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),$7,NULLIF($8,''),NULLIF($9,0),NULLIF($10,''),$11,$12::jsonb,$13::jsonb,now(),now())
		ON CONFLICT DO NOTHING
		RETURNING id::text`, firstRadarValue(event.Provider, SecurityRadarStreamProvider), firstRadarValue(event.StreamMode, SecurityRadarStreamModeLogs), normalizeRadarNetwork(event.Network), firstRadarValue(event.ModuleID, "unknown"), firstRadarValue(event.EventType, "stream_event"), strings.TrimSpace(event.Target), firstRadarValue(event.TargetType, "unknown"), strings.TrimSpace(event.Signature), event.Slot, strings.TrimSpace(event.ProgramID), firstRadarValue(event.EvidenceQuality, "raw_stream"), string(decoded), string(rawEvent)).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return id, err
}

func classifyRadarStreamText(text string) (string, string, string) {
	lower := strings.ToLower(text)
	raydiumProgram := strings.ToLower(defaultRaydiumProgramID)
	pumpProgram := strings.ToLower(defaultPumpProgramID)
	pumpSwapProgram := strings.ToLower(defaultPumpSwapProgramID)
	switch {
	case strings.Contains(lower, pumpSwapProgram):
		return ModulePumpSybilRadar, "pumpswap_trade_or_liquidity", defaultPumpSwapProgramID
	case strings.Contains(lower, pumpProgram):
		return ModulePumpSybilRadar, "pump_launch_or_trade", defaultPumpProgramID
	case strings.Contains(lower, raydiumProgram):
		return ModuleRaydiumPoolGuardian, "raydium_pool_or_liquidity", defaultRaydiumProgramID
	case strings.Contains(lower, "pump") || strings.Contains(lower, "pumpswap"):
		return ModulePumpSybilRadar, "pump_launch_or_trade", "pump"
	case strings.Contains(lower, "raydium") || strings.Contains(lower, "initialize2") || strings.Contains(lower, "amm"):
		return ModuleRaydiumPoolGuardian, "raydium_pool_or_liquidity", "raydium"
	case strings.Contains(lower, "initializemint") || strings.Contains(lower, "mintto") || strings.Contains(lower, "token program"):
		return ModulePumpSybilRadar, "spl_token_mint_activity", "spl_token"
	default:
		return "unknown", "stream_event", ""
	}
}

func extractRadarMintFromLogs(logs []string) string {
	for _, line := range logs {
		for _, field := range strings.Fields(line) {
			candidate := strings.Trim(field, " ,.;:()[]{}<>\"'")
			if isLikelyRadarSolanaAddress(candidate) {
				return candidate
			}
		}
	}
	return ""
}

func extractMintsFromTransactionMap(tx map[string]any) []string {
	seen := map[string]bool{}
	out := []string{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				lk := strings.ToLower(strings.TrimSpace(k))
				if lk == "mint" || lk == "tokenmint" || lk == "mintaddress" {
					candidate := strings.TrimSpace(anyString(val))
					if isLikelyRadarSolanaAddress(candidate) && !seen[candidate] {
						seen[candidate] = true
						out = append(out, candidate)
					}
				}
				walk(val)
			}
		case []any:
			for _, item := range x {
				walk(item)
			}
		}
	}
	walk(tx)
	return out
}

func targetTypeForRadarModule(moduleID string) string {
	if moduleID == ModuleRaydiumPoolGuardian {
		return "pool_or_token"
	}
	if moduleID == ModulePumpSybilRadar {
		return "token_or_launch"
	}
	return "unknown"
}
func evidenceQualityForRadarModule(moduleID string) string {
	if moduleID == "unknown" {
		return "raw_stream"
	}
	return "decoded_stream_hint"
}
func mergeRadarMaps(a, b map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range nonNilMap(a) {
		out[k] = v
	}
	for k, v := range nonNilMap(b) {
		out[k] = v
	}
	return out
}
func firstRadarValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
func asRadarMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}
func radarStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		out = append(out, anyString(item))
	}
	return out
}
func radarInt64(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	default:
		return 0
	}
}
func isLikelyRadarSolanaAddress(value string) bool {
	if len(value) < 32 || len(value) > 64 {
		return false
	}
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for _, r := range value {
		if !strings.ContainsRune(alphabet, r) {
			return false
		}
	}
	return true
}

type minimalWSConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func dialMinimalWebSocket(ctx context.Context, rawURL string) (*minimalWSConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return nil, fmt.Errorf("unsupported websocket scheme %s", u.Scheme)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "wss" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	d := net.Dialer{Timeout: 12 * time.Second}
	var conn net.Conn
	if u.Scheme == "wss" {
		raw, err := d.DialContext(ctx, "tcp", host)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(raw, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		conn = tlsConn
	} else {
		conn, err = d.DialContext(ctx, "tcp", host)
		if err != nil {
			return nil, err
		}
	}
	keyRaw := make([]byte, 16)
	_, _ = rand.Read(keyRaw)
	key := base64.StdEncoding.EncodeToString(keyRaw)
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: Koschei-SBX1/1.0\r\n\r\n", path, u.Host, key)
	if _, err := io.WriteString(conn, request); err != nil {
		_ = conn.Close()
		return nil, err
	}
	r := bufio.NewReader(conn)
	status, err := r.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if !strings.Contains(status, " 101 ") {
		_ = conn.Close()
		return nil, fmt.Errorf("websocket upgrade failed: %s", strings.TrimSpace(status))
	}
	accept := ""
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-accept:") {
			accept = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	if accept != websocketAccept(key) {
		_ = conn.Close()
		return nil, fmt.Errorf("websocket accept mismatch")
	}
	return &minimalWSConn{conn: conn, r: r}, nil
}

func websocketAccept(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h[:])
}
func (c *minimalWSConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}
func (c *minimalWSConn) WriteJSON(v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.writeFrame(0x1, payload)
}
func (c *minimalWSConn) Ping() error               { return c.writeFrame(0x9, []byte("koschei")) }
func (c *minimalWSConn) pong(payload []byte) error { return c.writeFrame(0xA, payload) }
func (c *minimalWSConn) writeFrame(opcode byte, payload []byte) error {
	var b bytes.Buffer
	b.WriteByte(0x80 | opcode)
	maskKey := make([]byte, 4)
	_, _ = rand.Read(maskKey)
	l := len(payload)
	if l < 126 {
		b.WriteByte(0x80 | byte(l))
	} else if l <= 65535 {
		b.WriteByte(0x80 | 126)
		_ = binary.Write(&b, binary.BigEndian, uint16(l))
	} else {
		b.WriteByte(0x80 | 127)
		_ = binary.Write(&b, binary.BigEndian, uint64(l))
	}
	b.Write(maskKey)
	masked := make([]byte, l)
	for i := range payload {
		masked[i] = payload[i] ^ maskKey[i%4]
	}
	b.Write(masked)
	_, err := c.conn.Write(b.Bytes())
	return err
}
func (c *minimalWSConn) ReadText(ctx context.Context) ([]byte, error) {
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(35 * time.Second))
		h1, err := c.r.ReadByte()
		if err != nil {
			return nil, err
		}
		h2, err := c.r.ReadByte()
		if err != nil {
			return nil, err
		}
		opcode := h1 & 0x0f
		masked := h2&0x80 != 0
		length := uint64(h2 & 0x7f)
		if length == 126 {
			var x uint16
			if err := binary.Read(c.r, binary.BigEndian, &x); err != nil {
				return nil, err
			}
			length = uint64(x)
		} else if length == 127 {
			if err := binary.Read(c.r, binary.BigEndian, &length); err != nil {
				return nil, err
			}
		}
		mask := []byte{0, 0, 0, 0}
		if masked {
			if _, err := io.ReadFull(c.r, mask); err != nil {
				return nil, err
			}
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(c.r, payload); err != nil {
			return nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
		switch opcode {
		case 0x1:
			return payload, nil
		case 0x8:
			return nil, io.EOF
		case 0x9:
			_ = c.pong(payload)
		case 0xA:
			continue
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
}
