package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type recipientRPCFixture struct {
	mu             sync.Mutex
	methods        []string
	signatureArgs  []string
	ownerQueries   []struct{ Owner, Mint string }
	creator        string
	recipient      string
	mint           string
	sourceATA      string
	destinationATA string
}

func (fixture *recipientRPCFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var request struct {
			JSONRPC string `json:"jsonrpc"`
			ID      int    `json:"id"`
			Method  string `json:"method"`
			Params  []any  `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode rpc request: %v", err)
		}
		fixture.mu.Lock()
		fixture.methods = append(fixture.methods, request.Method)
		fixture.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		write := func(result any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
		}

		switch request.Method {
		case "getTransaction":
			signature, _ := request.Params[0].(string)
			if signature == "creation-signature" {
				write(recipientCreationTransaction(fixture.creator, fixture.mint, fixture.sourceATA))
				return
			}
			if signature == "distribution-signature" {
				write(recipientDistributionTransaction(fixture.creator, fixture.recipient, fixture.mint, fixture.sourceATA, fixture.destinationATA))
				return
			}
			write(nil)
		case "getTokenAccountsByOwner":
			owner, _ := request.Params[0].(string)
			filter, _ := request.Params[1].(map[string]any)
			mint, _ := filter["mint"].(string)
			fixture.mu.Lock()
			fixture.ownerQueries = append(fixture.ownerQueries, struct{ Owner, Mint string }{owner, mint})
			fixture.mu.Unlock()
			switch owner {
			case fixture.creator:
				write(map[string]any{"value": []any{ownedTokenAccount(fixture.sourceATA, fixture.creator, fixture.mint, "900000000", 6, 900)}})
			case fixture.recipient:
				write(map[string]any{"value": []any{ownedTokenAccount(fixture.destinationATA, fixture.recipient, fixture.mint, "100000000", 6, 100)}})
			default:
				write(map[string]any{"value": []any{}})
			}
		case "getSignaturesForAddress":
			address, _ := request.Params[0].(string)
			fixture.mu.Lock()
			fixture.signatureArgs = append(fixture.signatureArgs, address)
			fixture.mu.Unlock()
			config, _ := request.Params[1].(map[string]any)
			before, _ := config["before"].(string)
			if address == fixture.sourceATA && before == "" {
				blockTime := int64(1700000200)
				write([]any{map[string]any{"signature": "distribution-signature", "slot": 200, "err": nil, "blockTime": blockTime}})
				return
			}
			write([]any{})
		case "getAccountInfo":
			write(map[string]any{"value": map[string]any{
				"data":       map[string]any{"parsed": map[string]any{"type": "mint", "info": map[string]any{}}},
				"executable": false, "lamports": 1, "owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "space": 82,
			}})
		case "getTokenSupply":
			write(map[string]any{"value": map[string]any{"amount": "1000000000", "decimals": 6, "uiAmount": 1000.0, "uiAmountString": "1000"}})
		case "getTokenLargestAccounts":
			write(map[string]any{"value": []any{map[string]any{"address": fixture.destinationATA, "amount": "100000000", "decimals": 6, "uiAmount": 100.0, "uiAmountString": "100"}}})
		case "getMultipleAccounts":
			addresses, _ := request.Params[0].([]any)
			values := make([]any, 0, len(addresses))
			for _, raw := range addresses {
				address, _ := raw.(string)
				if address == fixture.destinationATA {
					values = append(values, map[string]any{
						"data":       map[string]any{"parsed": map[string]any{"type": "account", "info": map[string]any{"owner": fixture.recipient, "mint": fixture.mint}}},
						"executable": false, "lamports": 1, "owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "space": 165,
					})
				} else if address == fixture.recipient {
					values = append(values, map[string]any{"data": map[string]any{}, "executable": false, "lamports": 1, "owner": solanaSystemProgramID, "space": 0})
				} else {
					values = append(values, nil)
				}
			}
			write(map[string]any{"value": values})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
		}
	}))
}

func TestInvestigateActorInitialRecipientsUsesMintSpecificATAOnly(t *testing.T) {
	resetSolanaRPCCachesForTest()
	fixture := &recipientRPCFixture{
		creator:        "Creator11111111111111111111111111111111111",
		recipient:      "Recipient111111111111111111111111111111111",
		mint:           "Mint111111111111111111111111111111111111111",
		sourceATA:      "SourceATA111111111111111111111111111111111",
		destinationATA: "DestinationATA1111111111111111111111111111",
	}
	server := fixture.server(t)
	defer server.Close()

	report := InvestigateActorInitialRecipients(context.Background(), server.URL, fixture.creator, fixture.mint, "creation-signature", ActorInitialRecipientOptions{
		MaxRecipients: 20, SignaturePageSize: 1, MaxPagesPerTokenATA: 2, MaxTransactionsParse: 10,
	})
	if report.Status != "initial_recipients_resolved" || !report.HistoryComplete {
		t.Fatalf("unexpected report status=%q complete=%v limitations=%v", report.Status, report.HistoryComplete, report.Limitations)
	}
	if len(report.Recipients) != 1 {
		t.Fatalf("recipients=%d", len(report.Recipients))
	}
	recipient := report.Recipients[0]
	if recipient.Wallet != fixture.recipient || recipient.Sequence != 1 {
		t.Fatalf("recipient=%#v", recipient)
	}
	if recipient.Fate != "became_top_holder" || !recipient.MatchesTopHolder || recipient.TopHolderRank != 1 {
		t.Fatalf("recipient fate=%#v", recipient)
	}
	if recipient.CurrentBalance != 100 || recipient.CurrentBalanceStatus != "current_balance_observed" {
		t.Fatalf("current fate=%#v", recipient)
	}

	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	for _, address := range fixture.signatureArgs {
		if address == fixture.recipient {
			t.Fatal("recipient-wide getSignaturesForAddress is prohibited")
		}
		if address != fixture.sourceATA {
			t.Fatalf("unexpected signature-history target %q", address)
		}
	}
	for _, query := range fixture.ownerQueries {
		if query.Mint != fixture.mint {
			t.Fatalf("non-mint-specific owner query: %#v", query)
		}
	}
}

func TestActorInitialRecipientEvidenceSeparatesCompleteAndBoundedHistory(t *testing.T) {
	report := ActorInitialRecipientReport{
		Mint:              "Mint111",
		CreatorWallet:     "Creator111",
		DistributionScope: "bounded_creator_token_account_history",
		HistoryComplete:   false,
		Recipients: []ActorInitialRecipient{{
			Sequence: 1, Wallet: "Recipient111", SourceTokenAccount: "SourceATA", DestinationTokenAccount: "DestATA",
			Amount: 10, Signature: "Sig111", Slot: 123, ObservedAt: time.Unix(1700000000, 0).UTC(),
			Program: "Tokenkeg", VerificationStatus: "verified", CurrentBalanceStatus: "zero_balance", Fate: "zero_balance",
		}},
	}
	bounded := ActorInitialRecipientEvidence(report, "solana-mainnet")
	if len(bounded) != 1 || bounded[0].Relation != "creator_recipient_in_window" {
		t.Fatalf("bounded evidence=%#v", bounded)
	}
	report.HistoryComplete = true
	report.DistributionScope = "complete_creator_token_account_history"
	complete := ActorInitialRecipientEvidence(report, "solana-mainnet")
	if len(complete) != 1 || complete[0].Relation != "initial_token_recipient" {
		t.Fatalf("complete evidence=%#v", complete)
	}
}

func TestActorRecipientTransferRequiresCreatorAuthorityAndMint(t *testing.T) {
	creator := "Creator111"
	mint := "Mint111"
	sourceATA := "SourceATA111"
	destinationATA := "DestinationATA111"
	blockTime := int64(1700000200)
	signature := SolanaSignatureInfo{Signature: "Sig111", Slot: 200, BlockTime: &blockTime}
	tx := recipientDistributionTransaction(creator, "Recipient111", mint, sourceATA, destinationATA)
	transfers := actorRecipientTransfersFromTransaction(tx, signature, creator, mint, map[string]bool{sourceATA: true})
	if len(transfers) != 1 {
		t.Fatalf("transfers=%d", len(transfers))
	}
	message := tx["transaction"].(map[string]any)["message"].(map[string]any)
	instruction := message["instructions"].([]any)[0].(map[string]any)
	instruction["parsed"].(map[string]any)["info"].(map[string]any)["authority"] = "OtherAuthority"
	if got := actorRecipientTransfersFromTransaction(tx, signature, creator, mint, map[string]bool{sourceATA: true}); len(got) != 0 {
		t.Fatalf("non-creator authority produced transfer: %#v", got)
	}
}

func recipientCreationTransaction(creator, mint, sourceATA string) map[string]any {
	return map[string]any{
		"blockTime": int64(1700000000),
		"meta": map[string]any{"err": nil, "preTokenBalances": []any{}, "postTokenBalances": []any{
			map[string]any{"accountIndex": float64(0), "owner": creator, "mint": mint, "uiTokenAmount": map[string]any{"amount": "1000000000", "decimals": float64(6), "uiAmount": 1000.0}},
		}},
		"transaction": map[string]any{"message": map[string]any{
			"accountKeys":  []any{map[string]any{"pubkey": sourceATA, "signer": false}, map[string]any{"pubkey": creator, "signer": true}},
			"instructions": []any{},
		}},
	}
}

func recipientDistributionTransaction(creator, recipient, mint, sourceATA, destinationATA string) map[string]any {
	return map[string]any{
		"blockTime": int64(1700000200),
		"meta": map[string]any{
			"err": nil,
			"preTokenBalances": []any{
				map[string]any{"accountIndex": float64(0), "owner": creator, "mint": mint, "uiTokenAmount": map[string]any{"amount": "1000000000", "decimals": float64(6), "uiAmount": 1000.0}},
			},
			"postTokenBalances": []any{
				map[string]any{"accountIndex": float64(0), "owner": creator, "mint": mint, "uiTokenAmount": map[string]any{"amount": "900000000", "decimals": float64(6), "uiAmount": 900.0}},
				map[string]any{"accountIndex": float64(1), "owner": recipient, "mint": mint, "uiTokenAmount": map[string]any{"amount": "100000000", "decimals": float64(6), "uiAmount": 100.0}},
			},
			"innerInstructions": []any{},
		},
		"transaction": map[string]any{"message": map[string]any{
			"accountKeys": []any{
				map[string]any{"pubkey": sourceATA, "signer": false},
				map[string]any{"pubkey": destinationATA, "signer": false},
				map[string]any{"pubkey": creator, "signer": true},
			},
			"instructions": []any{map[string]any{
				"program":   "spl-token",
				"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
				"parsed": map[string]any{"type": "transferChecked", "info": map[string]any{
					"source": sourceATA, "destination": destinationATA, "authority": creator, "mint": mint,
					"tokenAmount": map[string]any{"amount": "100000000", "decimals": float64(6), "uiAmount": 100.0, "uiAmountString": "100"},
				}},
			}},
		}},
	}
}

func ownedTokenAccount(pubkey, owner, mint, raw string, decimals int, ui float64) map[string]any {
	return map[string]any{
		"pubkey": pubkey,
		"account": map[string]any{"data": map[string]any{"parsed": map[string]any{
			"type": "account", "info": map[string]any{
				"mint": mint, "owner": owner, "state": "initialized",
				"tokenAmount": map[string]any{"amount": raw, "decimals": decimals, "uiAmount": ui, "uiAmountString": strings.TrimRight(strings.TrimRight(strconv.FormatFloat(ui, 'f', 6, 64), "0"), ".")},
			},
		}}},
	}
}
