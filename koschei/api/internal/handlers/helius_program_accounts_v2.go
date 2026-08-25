package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	heliusProgramAccountsV2PageLimit = 1000
	heliusProgramAccountsV2MaxPages  = 64
)

type heliusProgramAccountsV2Page struct {
	Context json.RawMessage `json:"context"`
	Value   struct {
		Accounts      []json.RawMessage `json:"accounts"`
		PaginationKey *string           `json:"paginationKey"`
	} `json:"value"`
	Accounts      []json.RawMessage `json:"accounts"`
	PaginationKey *string           `json:"paginationKey"`
}

type heliusProgramAccountsV2Context struct {
	Slot uint64 `json:"slot"`
}

// tryHeliusProgramAccountsV2 replaces standard getProgramAccounts only when the
// canonical RPC endpoint is Helius. Other providers retain the provider-neutral
// Solana method. The adapter normalizes Helius' paginated V2 response back into
// the standard getProgramAccounts result shape expected by existing collectors.
func (h *Handler) tryHeliusProgramAccountsV2(ctx context.Context, client *http.Client, rpcURL, network, method string, params interface{}, target interface{}) (bool, error) {
	if method != "getProgramAccounts" || !heliusProgramAccountsV2Enabled() {
		return false, nil
	}

	effectiveURL := strings.TrimSpace(rpcURL)
	if h != nil && h.SolanaRPC != nil {
		effectiveURL = strings.TrimSpace(h.SolanaRPC.URL(network))
	}
	if !isHeliusRPCProviderURL(effectiveURL) {
		return false, nil
	}

	program, config, ok := normalizeHeliusProgramAccountsV2Params(params)
	if !ok {
		// Unknown caller shapes keep the existing standard RPC path rather than
		// being reinterpreted by a provider-specific adapter.
		return false, nil
	}

	return true, h.fetchHeliusProgramAccountsV2(ctx, client, effectiveURL, network, program, config, target)
}

func heliusProgramAccountsV2Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("HELIUS_PROGRAM_ACCOUNTS_V2_ENABLED"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func isHeliusRPCProviderURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	return host == "helius-rpc.com" || strings.HasSuffix(host, ".helius-rpc.com")
}

func normalizeHeliusProgramAccountsV2Params(params interface{}) (string, map[string]any, bool) {
	values, ok := params.([]any)
	if !ok || len(values) == 0 {
		return "", nil, false
	}
	program, ok := values[0].(string)
	program = strings.TrimSpace(program)
	if !ok || program == "" {
		return "", nil, false
	}

	config := map[string]any{}
	if len(values) > 1 && values[1] != nil {
		encoded, err := json.Marshal(values[1])
		if err != nil || json.Unmarshal(encoded, &config) != nil {
			return "", nil, false
		}
	}
	delete(config, "paginationKey")
	delete(config, "limit")
	return program, config, true
}

func (h *Handler) fetchHeliusProgramAccountsV2(ctx context.Context, client *http.Client, rpcURL, network, program string, baseConfig map[string]any, target interface{}) error {
	withContext, _ := baseConfig["withContext"].(bool)
	accounts := make([]json.RawMessage, 0)
	seenCursors := map[string]bool{}
	var snapshotContext json.RawMessage
	var snapshotSlot uint64
	paginationKey := ""

	for pageNumber := 0; pageNumber < heliusProgramAccountsV2MaxPages; pageNumber++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		config := cloneProgramAccountsConfig(baseConfig)
		config["limit"] = heliusProgramAccountsV2PageLimit
		if paginationKey != "" {
			config["paginationKey"] = paginationKey
		}

		var page heliusProgramAccountsV2Page
		params := []any{program, config}
		if err := h.callHeliusProgramAccountsV2Page(ctx, client, rpcURL, network, params, &page); err != nil {
			return err
		}

		pageAccounts := page.Accounts
		pageCursor := page.PaginationKey
		if withContext {
			pageAccounts = page.Value.Accounts
			pageCursor = page.Value.PaginationKey
			var pageContext heliusProgramAccountsV2Context
			if len(page.Context) == 0 || json.Unmarshal(page.Context, &pageContext) != nil || pageContext.Slot == 0 {
				return fmt.Errorf("helius getProgramAccountsV2 missing context slot")
			}
			if snapshotSlot == 0 {
				snapshotSlot = pageContext.Slot
				snapshotContext = append(json.RawMessage(nil), page.Context...)
			} else if pageContext.Slot != snapshotSlot {
				return fmt.Errorf("helius getProgramAccountsV2 context slot changed across pages: %d -> %d", snapshotSlot, pageContext.Slot)
			}
		}
		accounts = append(accounts, pageAccounts...)

		if pageCursor == nil || strings.TrimSpace(*pageCursor) == "" {
			return normalizeHeliusProgramAccountsV2Result(withContext, snapshotContext, accounts, target)
		}
		next := strings.TrimSpace(*pageCursor)
		if seenCursors[next] {
			return fmt.Errorf("helius getProgramAccountsV2 repeated pagination key")
		}
		seenCursors[next] = true
		paginationKey = next
	}

	return fmt.Errorf("helius getProgramAccountsV2 exceeded %d pages without completion", heliusProgramAccountsV2MaxPages)
}

func (h *Handler) callHeliusProgramAccountsV2Page(ctx context.Context, client *http.Client, rpcURL, network string, params interface{}, target interface{}) error {
	if h != nil && h.SolanaRPC != nil {
		return h.SolanaRPC.Call(ctx, network, "getProgramAccountsV2", params, target, 0)
	}
	if client == nil {
		client = http.DefaultClient
	}
	return callSolanaRPC(client, rpcURL, "getProgramAccountsV2", params, target)
}

func cloneProgramAccountsConfig(input map[string]any) map[string]any {
	out := make(map[string]any, len(input)+2)
	for key, value := range input {
		out[key] = value
	}
	return out
}

func normalizeHeliusProgramAccountsV2Result(withContext bool, contextRaw json.RawMessage, accounts []json.RawMessage, target interface{}) error {
	var (
		encoded []byte
		err     error
	)
	if withContext {
		if len(contextRaw) == 0 {
			return fmt.Errorf("helius getProgramAccountsV2 context unavailable")
		}
		encoded, err = json.Marshal(map[string]any{
			"context": contextRaw,
			"value":   accounts,
		})
	} else {
		encoded, err = json.Marshal(accounts)
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		return fmt.Errorf("normalize helius getProgramAccountsV2 result: %w", err)
	}
	return nil
}
