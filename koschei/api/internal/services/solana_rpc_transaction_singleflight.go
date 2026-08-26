package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"koschei/api/internal/singleflight"
)

var solanaTransactionFetchGroup singleflight.Group

// solanaGetTransactionJSONParsedSingleflight suppresses identical in-flight
// transaction fetches before they consume the services RPC budget, local pacing
// slot, process-wide provider slot or upstream request. Completed responses are
// never cached.
func solanaGetTransactionJSONParsedSingleflight(ctx context.Context, rpcURL, signature string) (SolanaTransactionResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	rpcURL = strings.TrimSpace(rpcURL)
	signature = strings.TrimSpace(signature)
	key := solanaTransactionFetchKey(rpcURL, signature)

	value, err, _ := solanaTransactionFetchGroup.DoContext(ctx, key, func() (interface{}, error) {
		result, callErr := solanaRPCDo[SolanaTransactionResult](ctx, rpcURL, "getTransaction", []any{signature, map[string]any{
			"encoding":                       "jsonParsed",
			"commitment":                     "confirmed",
			"maxSupportedTransactionVersion": 0,
		}})
		if callErr != nil {
			return nil, callErr
		}
		// Serialize once so every caller receives an independent map. Sharing the
		// same nested map between ARVIS collectors would introduce mutation races.
		encoded, encodeErr := json.Marshal(result)
		if encodeErr != nil {
			return nil, fmt.Errorf("snapshot solana transaction result: %w", encodeErr)
		}
		return encoded, nil
	})
	if err != nil {
		return nil, err
	}
	encoded, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("solana transaction singleflight returned invalid snapshot")
	}
	var result SolanaTransactionResult
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, fmt.Errorf("restore solana transaction result: %w", err)
	}
	return result, nil
}

func solanaTransactionFetchKey(rpcURL, signature string) string {
	// The endpoint may contain a provider credential. Hash it with the exact
	// request identity so the singleflight map never retains or logs raw keys.
	material := strings.TrimSpace(rpcURL) + "\ngetTransaction\n" + strings.TrimSpace(signature) + "\njsonParsed\nconfirmed\n0"
	digest := sha256.Sum256([]byte(material))
	return hex.EncodeToString(digest[:])
}
