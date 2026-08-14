package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"koschei/api/internal/router"
)

func jsonBytes(v any) []byte { b, _ := json.Marshal(v); return b }
func userEmail(w http.ResponseWriter, r *http.Request) (string, bool) {
	c, ok := userFromContext(r.Context())
	if !ok || normalizedClaimEmail(c) == "" {
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return "", false
	}
	return normalizedClaimEmail(c), true
}
func (h *Handler) logTool(email, tool, status string) {
	if h.DB == nil {
		return
	}
	_, _ = h.DB.Exec(`INSERT INTO tool_usage_logs(email,tool_key,status) VALUES(NULLIF($1,''),$2,$3)`, email, tool, status)
}
func (h *Handler) trackEvent(email, name, path string) {
	if h.DB == nil {
		return
	}
	_, _ = h.DB.Exec(`INSERT INTO analytics_events(event_name,email,path,metadata) VALUES($1,NULLIF($2,''),$3,'{}'::jsonb)`, name, email, path)
}

func (h *Handler) spendOutput(email, tool string) error {
	tx, e := h.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = h.applyCreditChargeTxWithReason(tx, "", email, tool); e != nil {
		return e
	}
	return tx.Commit()
}

func (h *Handler) useOutput(w http.ResponseWriter, email, tool string) bool {
	if e := h.spendOutput(email, tool); e != nil {
		writeJSON(w, 402, insufficientOutputsResponse())
		return false
	}
	return true
}

type grantRequest struct {
	Ecosystem     string `json:"ecosystem"`
	OpportunityID string `json:"opportunity_id"`
	Focus         string `json:"focus"`
	GeneratedText string `json:"generated_text"`
	Title         string `json:"title"`
}

func grantContent(ec, focus string) map[string]any {
	if ec == "" {
		ec = "Ethereum"
	}
	if focus == "" {
		focus = "Web3 intelligence and developer tooling"
	}
	m := []string{"Ship ecosystem-specific read-only intelligence workflows", "Publish measurable public proof-of-impact metrics", "Deliver developer docs and integration references"}
	text := fmt.Sprintf("%s Grant Application — Koschei Web3 Intelligence OS\n\nPROJECT SUMMARY\nKoschei is an AI-powered, no-custody, read-only Web3 intelligence and developer tooling platform focused on %s.\n\nGRANT FIT\nReusable public-good infrastructure and transparent impact metrics for %s.\n\nMILESTONES\n1. %s\n2. %s\n3. %s\n\nESTIMATED BUDGET\n$25,000 preliminary request. No automatic submission is performed.", ec, focus, ec, m[0], m[1], m[2])
	return map[string]any{"ecosystem": ec, "project_summary": "Koschei Web3 Intelligence OS: no-custody intelligence for builders.", "grant_fit_reasoning": "Reusable developer tooling and ecosystem-aligned safety workflows.", "milestones": m, "estimated_budget": map[string]any{"currency": "USD", "estimated_total": 25000}, "generated_text": text}
}
func (h *Handler) GrantAutopilot(w http.ResponseWriter, r *http.Request) {
	if !h.ownerAuth(w, r) {
		return
	}
	rows, e := h.DB.Query(`SELECT id,ecosystem,title,status,generated_text,created_at FROM grant_applications ORDER BY created_at DESC LIMIT 50`)
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": "db_failed"})
		return
	}
	defer rows.Close()
	a := []map[string]any{}
	for rows.Next() {
		var id, ec, t, s, g string
		var c any
		_ = rows.Scan(&id, &ec, &t, &s, &g, &c)
		a = append(a, map[string]any{"id": id, "ecosystem": ec, "title": t, "status": s, "generated_text": g, "created_at": c})
	}
	writeJSON(w, 200, map[string]any{"applications": a})
}
func (h *Handler) GrantGenerate(w http.ResponseWriter, r *http.Request) {
	if !h.ownerAuth(w, r) {
		return
	}
	var q grantRequest
	if decodeJSON(r, &q) != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_body"})
		return
	}
	if q.Ecosystem == "" {
		q.Ecosystem = "Solana"
	}
	if q.Focus == "" {
		q.Focus = "Web3 developer tooling, security and intelligence"
	}

	prompt := fmt.Sprintf(`You are an expert grant writer for Web3 and blockchain projects. Write a compelling, professional grant application for the following project.

PROJECT: Koschei Web3 Intelligence OS
WEBSITE: https://tradepigloball.co
TARGET ECOSYSTEM: %s
FOCUS AREA: %s

WHAT KOSCHEI DOES:
- AI-powered Solana Program Security Scanner (detect vulnerabilities in smart contracts)
- Real-time chain health monitoring for 6 networks (Solana, ETH, Base, Arbitrum, Polygon, Optimism)
- TX Decoder: explains any Solana transaction in plain English with risk scoring
- Wallet Reputation Score: 0-100 trust score for any Solana wallet
- AI Metadata Studio: generate NFT and game asset metadata
- On-chain Risk Scanner with behavioral analysis
- Watchlist: monitor wallets and contracts through Alchemy API polling
- Intelligence Graph: visual on-chain relationship mapping
- Cross-chain risk analysis and Sybil detection
- No custody, no private keys, read-only architecture
- Open REST API (public endpoints, no auth required for chain health)
- Built with Go backend + static HTML frontend, deployed on Railway

STACK: Go, PostgreSQL (Neon), Neon Auth, Alchemy, Together AI, Railway

Write a grant application with these sections:
1. EXECUTIVE SUMMARY (2-3 sentences, punchy)
2. PROBLEM STATEMENT (what problem does this solve for %s developers)
3. SOLUTION (how Koschei solves it)
4. ECOSYSTEM VALUE (why this matters for %s specifically)
5. MILESTONES (3 concrete, measurable milestones with timeframes)
6. BUDGET JUSTIFICATION (for $25,000 - $50,000 range)
7. TEAM (solo developer from Turkey, building since 2024)

Be specific, compelling, and avoid generic Web3 jargon. Focus on real impact.
Write in plain text, no markdown headers, just section titles in CAPS.`, q.Ecosystem, q.Focus, q.Ecosystem, q.Ecosystem)

	ai, err := router.Chat(r.Context(), router.ChatRequest{Prompt: prompt, MaxTokens: 1200, Temperature: 0.7, Timeout: 30 * time.Second})
	if err != nil {
		h.logTool("", "grant_autopilot", "ai_error")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "ai_unavailable", "message": "Unable to fetch live data right now."})
		return
	}
	generatedText := strings.TrimSpace(ai.Content)
	if generatedText == "" {
		h.logTool("", "grant_autopilot", "empty_ai_response")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "ai_empty_response", "message": "Unable to fetch live data right now."})
		return
	}

	milestones := []string{
		"Month 1-2: Ship Program Security Scanner with automated vulnerability detection and public API",
		"Month 3-4: Launch x402 micropayment integration and SDK for developer adoption",
		"Month 5-6: Deploy Compliance Dashboard for enterprise users, reach 500+ API users",
	}

	h.logTool("", "grant_autopilot", "generated")
	h.trackEvent("", "grant_autopilot_generate", r.URL.Path)

	writeJSON(w, 200, map[string]any{
		"ecosystem":           q.Ecosystem,
		"project_summary":     "Koschei Web3 Intelligence OS: AI-powered, no-custody developer tooling for the Solana ecosystem.",
		"grant_fit_reasoning": fmt.Sprintf("Koschei provides public-good infrastructure for %s developers with open APIs, security tooling, and AI-powered analysis.", q.Ecosystem),
		"milestones":          milestones,
		"estimated_budget":    map[string]any{"currency": "USD", "estimated_total": 25000},
		"generated_text":      generatedText,
		"ai_powered":          true,
	})
}
func (h *Handler) GrantSave(w http.ResponseWriter, r *http.Request) {
	if !h.ownerAuth(w, r) {
		return
	}
	var q grantRequest
	if decodeJSON(r, &q) != nil || q.GeneratedText == "" {
		writeJSON(w, 400, map[string]string{"error": "generated_text_required"})
		return
	}
	var id string
	if h.DB.QueryRow(`INSERT INTO grant_applications(ecosystem,title,generated_text) VALUES($1,$2,$3) RETURNING id`, q.Ecosystem, q.Title, q.GeneratedText).Scan(&id) != nil {
		writeJSON(w, 500, map[string]string{"error": "db_failed"})
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true, "id": id})
}

type fundingAssistantInput struct {
	ProjectName      string `json:"project_name"`
	Ecosystem        string `json:"ecosystem"`
	ProjectCategory  string `json:"project_category"`
	ShortDescription string `json:"short_description"`
	RequestedAmount  string `json:"requested_amount"`
	MilestoneCount   int    `json:"milestone_count"`
	Notes            string `json:"notes"`
}

func fundingAssistantDraft(q fundingAssistantInput) map[string]any {
	if q.MilestoneCount < 1 {
		q.MilestoneCount = 3
	}
	if q.MilestoneCount > 12 {
		q.MilestoneCount = 12
	}
	if q.Ecosystem == "" {
		q.Ecosystem = "Custom"
	}
	milestones := []map[string]string{}
	for i := 1; i <= q.MilestoneCount; i++ {
		milestones = append(milestones, map[string]string{
			"title":       fmt.Sprintf("Milestone %d", i),
			"deliverable": fmt.Sprintf("Deliver and document phase %d of %s", i, q.ProjectName),
			"evidence":    "Public release notes, usage metrics, and ecosystem feedback",
		})
	}
	amount := q.RequestedAmount
	if amount == "" {
		amount = "To be confirmed with the funding program"
	}
	problem := fmt.Sprintf("Builders in %s need clearer, accessible tooling in the %s category.", q.Ecosystem, q.ProjectCategory)
	solution := q.ShortDescription
	impact := fmt.Sprintf("Provide measurable, no-custody value for %s builders and publish progress evidence.", q.Ecosystem)
	application := fmt.Sprintf("PROJECT SUMMARY\n%s is a %s project for %s. %s\n\nPROBLEM\n%s\n\nSOLUTION\n%s\n\nIMPACT\n%s\n\nBUDGET DRAFT\nRequested amount: %s\n\nNOTES\n%s", q.ProjectName, q.ProjectCategory, q.Ecosystem, q.ShortDescription, problem, solution, impact, amount, q.Notes)
	return map[string]any{
		"project_summary":             fmt.Sprintf("%s — %s", q.ProjectName, q.ShortDescription),
		"problem":                     problem,
		"solution":                    solution,
		"impact":                      impact,
		"milestones":                  milestones,
		"budget_draft":                map[string]any{"requested_amount": amount, "status": "draft", "automatic_submission": false},
		"application_text":            application,
		"copy_ready_application_text": application,
		"disclaimer":                  "Draft preparation only. Review program requirements before submitting.",
	}
}

func (h *Handler) FundingAssistant(w http.ResponseWriter, r *http.Request) {
	email, ok := userEmail(w, r)
	if !ok {
		return
	}
	var q fundingAssistantInput
	if decodeJSON(r, &q) != nil || strings.TrimSpace(q.ProjectName) == "" || strings.TrimSpace(q.ShortDescription) == "" {
		writeJSON(w, 400, map[string]string{"error": "project_name_and_short_description_required"})
		return
	}
	draft := fundingAssistantDraft(q)
	h.logTool(email, "funding_assistant", "completed")
	h.trackEvent(email, "funding_assistant_generate", r.URL.Path)
	writeJSON(w, 200, map[string]any{"ok": true, "draft": draft})
}

func (h *Handler) IntelligenceGraph(w http.ResponseWriter, r *http.Request) {
	email, ok := userEmail(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		var q struct {
			SourceID string `json:"source_id"`
			Address  string `json:"address"`
			Chain    string `json:"chain"`
			Network  string `json:"network"`
		}
		if decodeJSON(r, &q) != nil || (strings.TrimSpace(q.SourceID) == "" && strings.TrimSpace(q.Address) == "") {
			writeJSON(w, 400, map[string]string{"error": "source_id_or_address_required"})
			return
		}
		_, _ = h.DB.Exec(`DELETE FROM intelligence_graph_edges WHERE lower(email)=lower($1)`, email)
		_, _ = h.DB.Exec(`DELETE FROM intelligence_graph_nodes WHERE lower(email)=lower($1)`, email)
		if strings.TrimSpace(q.Address) != "" {
			_, _ = h.DB.Exec(`INSERT INTO intelligence_graph_nodes(email,node_type,chain,network,address,label,metadata) VALUES($1,'submitted_address',$2,$3,$4,$4,'{}'::jsonb)`, email, q.Chain, q.Network, q.Address)
		}
		rows, _ := h.DB.Query(`SELECT id,COALESCE(label,name,''),COALESCE(chain,''),COALESCE(network,''),COALESCE(address,'') FROM web3_event_sources WHERE lower(email)=lower($1) AND id::text=$2`, email, q.SourceID)
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var sourceID, label, chain, network, address, graphSourceID string
				_ = rows.Scan(&sourceID, &label, &chain, &network, &address)
				if h.DB.QueryRow(`INSERT INTO intelligence_graph_nodes(email,node_type,chain,network,address,label,metadata) VALUES($1,'source',$2,$3,$4,$5,$6) RETURNING id`, email, chain, network, address, label, jsonBytes(map[string]string{"source_id": sourceID})).Scan(&graphSourceID) != nil {
					continue
				}
				events, _ := h.DB.Query(`SELECT COALESCE(tx_hash,''),COALESCE(contract_address,''),COALESCE(event_type,'activity') FROM web3_events WHERE source_id=$1 AND tx_hash IS NOT NULL ORDER BY created_at DESC LIMIT 25`, sourceID)
				if events != nil {
					for events.Next() {
						var hash, contract, eventType, eventNodeID string
						_ = events.Scan(&hash, &contract, &eventType)
						label := hash
						nodeType := "transaction"
						if contract != "" {
							label = contract
							nodeType = "contract"
						}
						if h.DB.QueryRow(`INSERT INTO intelligence_graph_nodes(email,node_type,chain,network,address,label,metadata) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`, email, nodeType, chain, network, contract, label, jsonBytes(map[string]string{"tx_hash": hash})).Scan(&eventNodeID) == nil {
							_, _ = h.DB.Exec(`INSERT INTO intelligence_graph_edges(email,source_node_id,target_node_id,relationship_type,chain,network,tx_hash) VALUES($1,$2,$3,$4,$5,$6,$7)`, email, graphSourceID, eventNodeID, eventType, chain, network, hash)
						}
					}
					events.Close()
				}
			}
		}
		h.logTool(email, "intelligence_graph", "built")
		h.trackEvent(email, "graph_build", r.URL.Path)
	}
	rows, _ := h.DB.Query(`SELECT id,node_type,COALESCE(chain,''),COALESCE(network,''),COALESCE(address,''),COALESCE(label,''),risk_score FROM intelligence_graph_nodes WHERE lower(email)=lower($1)`, email)
	nodes := []map[string]any{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, t, c, n, a, l string
			var score int
			_ = rows.Scan(&id, &t, &c, &n, &a, &l, &score)
			nodes = append(nodes, map[string]any{"id": id, "node_type": t, "chain": c, "network": n, "address": a, "label": l, "risk_score": score})
		}
	}
	edges := []map[string]any{}
	erows, _ := h.DB.Query(`SELECT source_node_id,target_node_id,relationship_type,COALESCE(chain,''),COALESCE(network,''),COALESCE(tx_hash,'') FROM intelligence_graph_edges WHERE lower(email)=lower($1)`, email)
	if erows != nil {
		defer erows.Close()
		for erows.Next() {
			var source, target, rel, chain, network, hash string
			_ = erows.Scan(&source, &target, &rel, &chain, &network, &hash)
			edges = append(edges, map[string]any{"source": source, "target": target, "relationship_type": rel, "chain": chain, "network": network, "tx_hash": hash})
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "preliminary": true, "nodes": nodes, "edges": edges, "relationship_summary": fmt.Sprintf("Built %d nodes and %d relationships from your submitted address or watchlist activity.", len(nodes), len(edges))})
}

type riskInput struct {
	Target     string `json:"target"`
	Chain      string `json:"chain"`
	Network    string `json:"network"`
	TargetType string `json:"target_type"`
	Notes      string `json:"notes"`
}

func riskResult(q riskInput) (int, string, []string, []string, []string) {
	score := 25
	f := []string{}
	if q.Target == "" {
		score = 55
		f = append(f, "Missing target information")
	}
	if q.TargetType == "contract" {
		score += 15
		f = append(f, "Contract behavior is not independently verified")
	}
	if q.Notes == "" {
		f = append(f, "No contextual notes supplied")
	}
	s := "low"
	if score >= 75 {
		s = "critical"
	} else if score >= 55 {
		s = "high"
	} else if score >= 30 {
		s = "medium"
	}
	return score, s, f, []string{"Preliminary heuristic assessment; not a guarantee."}, []string{"Review activity and provenance manually", "Verify addresses using trusted explorers", "Never rely on this preliminary score alone"}
}
func (h *Handler) RiskV2(w http.ResponseWriter, r *http.Request) {
	email, ok := userEmail(w, r)
	if !ok {
		return
	}
	var q riskInput
	if decodeJSON(r, &q) != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_body"})
		return
	}
	if !h.useOutput(w, email, "risk_v2") {
		return
	}
	score, sev, f, e, rec := riskResult(q)
	_, _ = h.DB.Exec(`INSERT INTO risk_assessments(email,target,chain,network,target_type,risk_score,severity,red_flags,evidence,recommendations,raw_context) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, email, q.Target, q.Chain, q.Network, q.TargetType, score, sev, jsonBytes(f), jsonBytes(e), jsonBytes(rec), jsonBytes(q))
	h.logTool(email, "risk_v2", "completed")
	h.trackEvent(email, "risk_v2_scan", r.URL.Path)
	writeJSON(w, 200, map[string]any{"ok": true, "preliminary": true, "risk_score": score, "severity": sev, "red_flags": f, "evidence": e, "recommendations": rec, "disclaimer": "Preliminary risk intelligence. Not financial, legal, or security advice."})
}
func evmDecode(chain, network, hash string) (map[string]any, bool) {
	key := strings.TrimSpace(os.Getenv("ALCHEMY_API_KEY"))
	if key == "" {
		return nil, false
	}
	chain, network = strings.ToLower(strings.TrimSpace(chain)), strings.ToLower(strings.TrimSpace(network))
	endpoint := ""
	switch {
	case chain == "base" && (network == "base-mainnet" || network == "mainnet" || network == "base"):
		endpoint = "https://base-mainnet.g.alchemy.com/v2/" + key
	case chain == "base" && (network == "sepolia" || network == "base-sepolia"):
		endpoint = "https://base-sepolia.g.alchemy.com/v2/" + key
	case (chain == "ethereum" || chain == "eth") && (network == "mainnet" || network == "ethereum-mainnet"):
		endpoint = "https://eth-mainnet.g.alchemy.com/v2/" + key
	case (chain == "ethereum" || chain == "eth") && (network == "sepolia" || network == "eth-sepolia"):
		endpoint = "https://eth-sepolia.g.alchemy.com/v2/" + key
	}
	if endpoint == "" {
		return nil, false
	}
	call := func(method string) map[string]any {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": []string{hash}})
		req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 8 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var parsed struct {
			Result map[string]any `json:"result"`
		}
		if json.Unmarshal(b, &parsed) != nil {
			return nil
		}
		return parsed.Result
	}
	tx, receipt := call("eth_getTransactionByHash"), call("eth_getTransactionReceipt")
	if tx == nil {
		return nil, false
	}
	logs := 0
	if values, ok := receipt["logs"].([]any); ok {
		logs = len(values)
	}
	status := "unknown"
	if receipt["status"] == "0x1" {
		status = "success"
	} else if receipt["status"] == "0x0" {
		status = "failure"
	}
	return map[string]any{"from": tx["from"], "to": tx["to"], "value": tx["value"], "status": status, "logs_count": logs, "risk_hints": []string{"Review approvals, logs, and destination before relying on this decode"}, "provider": "alchemy"}, true
}

func (h *Handler) TXDecodePro(w http.ResponseWriter, r *http.Request) {
	email, ok := userEmail(w, r)
	if !ok {
		return
	}
	var q struct {
		Chain   string `json:"chain"`
		Network string `json:"network"`
		TxHash  string `json:"tx_hash"`
	}
	if decodeJSON(r, &q) != nil || q.TxHash == "" {
		writeJSON(w, 400, map[string]string{"error": "tx_hash_required"})
		return
	}
	if !h.useOutput(w, email, "tx_decode_pro") {
		return
	}
	summary := fmt.Sprintf("Preliminary %s transaction summary. Confirm details with a trusted explorer.", strings.ToUpper(q.Chain))
	d := map[string]any{"from": "unknown", "to": "unknown", "value": "unknown", "status": "unknown", "logs_count": 0, "risk_hints": []string{"Unknown transaction context", "Manual verification recommended"}, "provider_configured": os.Getenv("ALCHEMY_API_KEY") != ""}
	if live, ok := evmDecode(q.Chain, q.Network, q.TxHash); ok {
		d = live
		summary = fmt.Sprintf("Alchemy-backed %s transaction decode. Confirm details with a trusted explorer.", strings.ToUpper(q.Chain))
	}
	_, _ = h.DB.Exec(`INSERT INTO tx_decodes(email,chain,network,tx_hash,summary,risk_score,decoded) VALUES($1,$2,$3,$4,$5,35,$6)`, email, q.Chain, q.Network, q.TxHash, summary, jsonBytes(d))
	h.logTool(email, "tx_decode_pro", "completed")
	h.trackEvent(email, "tx_decode_pro_decode", r.URL.Path)
	writeJSON(w, 200, map[string]any{"ok": true, "preliminary": true, "human_summary": summary, "summary": summary, "risk_score": 35, "from": d["from"], "to": d["to"], "value": d["value"], "status": d["status"], "logs_count": d["logs_count"], "risk_hints": d["risk_hints"], "raw": d, "decoded": d})
}

type crossInput struct {
	SourceChain string `json:"source_chain"`
	TargetChain string `json:"target_chain"`
	Address     string `json:"address"`
	TxHash      string `json:"tx_hash"`
	Bridge      string `json:"bridge_or_protocol"`
}

func (h *Handler) CrossChainRisk(w http.ResponseWriter, r *http.Request) {
	email, ok := userEmail(w, r)
	if !ok {
		return
	}
	var q crossInput
	if decodeJSON(r, &q) != nil || (q.Address == "" && q.TxHash == "") {
		writeJSON(w, 400, map[string]string{"error": "address_or_tx_hash_required"})
		return
	}
	if !h.useOutput(w, email, "cross_chain_risk") {
		return
	}
	checks := []string{"Bridge/protocol trust review", "Route and destination confirmation", "Liquidity and finality review", "Manual explorer verification"}
	score := 40
	if q.Bridge == "" {
		score = 55
		checks = append(checks, "Unknown route/protocol warning")
	}
	summary := "Preliminary cross-chain checklist only; no bridge detection is claimed."
	h.trackEvent(email, "cross_chain_risk_scan", r.URL.Path)
	_, _ = h.DB.Exec(`INSERT INTO cross_chain_observations(email,source_chain,target_chain,address,tx_hash,bridge_or_protocol,risk_score,observation_type,summary,raw_payload) VALUES($1,$2,$3,$4,$5,$6,$7,'submitted_check',$8,$9)`, email, q.SourceChain, q.TargetChain, q.Address, q.TxHash, q.Bridge, score, summary, jsonBytes(q))
	writeJSON(w, 200, map[string]any{"ok": true, "preliminary": true, "risk_score": score, "observation_type": "submitted_check", "summary": summary, "checklist": checks, "recommendations": []string{"Manual review required before acting.", "Confirm the route and protocol with trusted explorers."}})
}
func (h *Handler) SybilCheck(w http.ResponseWriter, r *http.Request) {
	email, ok := userEmail(w, r)
	if !ok {
		return
	}
	var q struct {
		Subject   string `json:"subject"`
		CheckType string `json:"check_type"`
	}
	if decodeJSON(r, &q) != nil || q.Subject == "" {
		writeJSON(w, 400, map[string]string{"error": "subject_required"})
		return
	}
	h.trackEvent(email, "sybil_check_scan", r.URL.Path)
	sig := []string{}
	var accountCount int
	if err := h.DB.QueryRow(`SELECT count(DISTINCT lower(email)) FROM web3_event_sources WHERE lower(address)=lower($1)`, q.Subject).Scan(&accountCount); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "partial_failures": []map[string]string{{"source": "database", "code": APICodeIntegrationError, "message": "Real data unavailable"}}})
		return
	}
	if accountCount > 1 {
		sig = append(sig, "The same public wallet appears across multiple accounts")
	}
	rec := "No Sybil conclusion is produced without real linked activity signals; review public activity manually."
	_, _ = h.DB.Exec(`INSERT INTO sybil_checks(email,subject,check_type,score,signals,recommendation) VALUES($1,$2,$3,NULL,$4,$5)`, email, q.Subject, q.CheckType, jsonBytes(sig), rec)
	writeJSON(w, 200, map[string]any{"ok": true, "signals": sig, "linked_account_count": accountCount, "recommendation": rec, "privacy": "No biometric data. No identity documents. No private keys."})
}

func (h *Handler) ToolPrices(w http.ResponseWriter, r *http.Request) {
	rows, e := h.DB.Query(`SELECT tool_key,display_name,price_usd,payment_mode FROM tool_usage_prices ORDER BY tool_key`)
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": "db_failed"})
		return
	}
	defer rows.Close()
	a := []map[string]any{}
	for rows.Next() {
		var k, n, m string
		var p float64
		_ = rows.Scan(&k, &n, &p, &m)
		a = append(a, map[string]any{"tool_key": k, "display_name": n, "price_usd": p, "payment_mode": m, "enforced": os.Getenv("KOSCHEI_X402_ENABLED") == "true" && m == "x402_ready"})
	}
	writeJSON(w, 200, map[string]any{"ok": true, "x402_enabled": os.Getenv("KOSCHEI_X402_ENABLED") == "true", "tools": a})
}
func defaultAgentScopes() []string {
	return []string{"health", "wallet_score", "risk_summary", "metadata_template", "chain_health"}
}

func agentScopeForPath(path string) string {
	switch path {
	case "/api/agent/health":
		return "health"
	case "/api/agent/wallet-score":
		return "wallet_score"
	case "/api/agent/risk-summary":
		return "risk_summary"
	case "/api/agent/metadata-template":
		return "metadata_template"
	case "/api/agent/chain-health":
		return "chain_health"
	default:
		return ""
	}
}

func hasAgentScope(scopes []string, required string) bool {
	if len(scopes) == 0 {
		scopes = defaultAgentScopes()
	}
	for _, scope := range scopes {
		if strings.EqualFold(strings.TrimSpace(scope), required) {
			return true
		}
	}
	return false
}

func (h *Handler) logAgentUsage(keyID, endpoint, status string) {
	_, _ = h.DB.Exec(`INSERT INTO agent_api_logs(key_id,endpoint,status) VALUES(NULLIF($1,'')::uuid,$2,$3)`, keyID, endpoint, status)
}

func (h *Handler) AgentTool(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(r.Header.Get("x-koschei-agent-key"))
	if key == "" {
		writeJSON(w, 401, map[string]string{"error": "invalid_agent_key"})
		return
	}
	if h.Limiter != nil && !h.Limiter.allow("agent-ip:"+clientIP(r), 120, time.Minute) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
		return
	}
	keyFingerprint := sha256.Sum256([]byte(key))
	if h.Limiter != nil && !h.Limiter.allow("agent-key:"+hex.EncodeToString(keyFingerprint[:]), 60, time.Minute) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
		return
	}
	sum := sha256.Sum256([]byte(key))
	var id string
	var rawScopes []byte
	if h.DB.QueryRow(`SELECT id, COALESCE(scopes,'[]'::jsonb) FROM agent_api_keys WHERE key_hash=$1 AND status='active'`, hex.EncodeToString(sum[:])).Scan(&id, &rawScopes) != nil {
		writeJSON(w, 401, map[string]string{"error": "invalid_agent_key"})
		return
	}
	requiredScope := agentScopeForPath(r.URL.Path)
	if requiredScope == "" {
		h.logAgentUsage(id, r.URL.Path, "forbidden")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	var scopes []string
	_ = json.Unmarshal(rawScopes, &scopes)
	if !hasAgentScope(scopes, requiredScope) {
		h.logAgentUsage(id, r.URL.Path, "forbidden")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	_, _ = h.DB.Exec(`UPDATE agent_api_keys SET last_used_at=now() WHERE id=$1`, id)
	h.logAgentUsage(id, r.URL.Path, "ok")
	h.logTool("", "agent_api_call", "ok")
	h.trackEvent("", "agent_api_call", r.URL.Path)
	if r.URL.Path == "/api/agent/health" {
		writeJSON(w, 200, map[string]any{"ok": true, "service": "Koschei Agent API", "mode": "read-only"})
		return
	}
	if r.URL.Path == "/api/agent/wallet-score" || r.URL.Path == "/api/agent/metadata-template" || r.URL.Path == "/api/agent/chain-health" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "real_data_unavailable", "message": "Real data unavailable. Analysis could not be completed."})
		return
	}
	var q riskInput
	if r.URL.Path != "/api/agent/risk-summary" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	_ = decodeJSON(r, &q)
	score, sev, f, e, rec := riskResult(q)
	writeJSON(w, 200, map[string]any{"ok": true, "preliminary": true, "risk_score": score, "severity": sev, "red_flags": f, "evidence": e, "recommendations": rec, "disclaimer": "Preliminary risk intelligence. Not financial, legal, or security advice."})
}
