package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type actorFundingRPCFixture struct {
	mu           sync.Mutex
	pageRequests []map[string]any
	pages        map[string][]SolanaSignatureInfo
	transactions map[string]map[string]any
}

func (fixture *actorFundingRPCFixture) server(t *testing.T) *httptest.Server {
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
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case "getSignaturesForAddress":
			config := map[string]any{}
			if len(request.Params) > 1 {
				config, _ = request.Params[1].(map[string]any)
			}
			fixture.mu.Lock()
			fixture.pageRequests = append(fixture.pageRequests, config)
			before, _ := config["before"].(string)
			rows := fixture.pages[before]
			fixture.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": rows})
		case "getTransaction":
			signature, _ := request.Params[0].(string)
			fixture.mu.Lock()
			tx := fixture.transactions[signature]
			fixture.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": tx})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
		}
	}))
}

func TestFindActorFundingOriginCompleteHistory(t *testing.T) {
	resetSolanaRPCCachesForTest()
	wallet := "Wallet111111111111111111111111111111111111"
	funder := "Funder111111111111111111111111111111111111"
	oldTime, newTime := int64(1700000000), int64(1700003600)
	fixture := &actorFundingRPCFixture{
		pages: map[string][]SolanaSignatureInfo{
			"": {
				{Signature: "newer-signature", Slot: 200, BlockTime: &newTime},
				{Signature: "funding-signature", Slot: 100, BlockTime: &oldTime},
			},
			"funding-signature": {},
		},
		transactions: map[string]map[string]any{
			"funding-signature": fundingTransaction(wallet, funder, 1_500_000_000, oldTime, true, "transfer"),
			"newer-signature":   outgoingTransaction(wallet, "Other1111111111111111111111111111111111111", newTime),
		},
	}
	server := fixture.server(t)
	defer server.Close()

	result, err := FindActorFundingOrigin(context.Background(), server.URL, wallet, ActorFundingOriginOptions{
		PageSize: 2, MaxPages: 3, OldestTransactionsToParse: 10,
	})
	if err != nil {
		t.Fatalf("find funding origin: %v", err)
	}
	if !result.HistoryComplete {
		t.Fatal("expected complete signature history")
	}
	if result.Status != "initial_funding_observed" {
		t.Fatalf("status=%q", result.Status)
	}
	if result.VerificationStatus != "verified" {
		t.Fatalf("verification=%q", result.VerificationStatus)
	}
	if result.SourceWallet != funder || result.DestinationWallet != wallet {
		t.Fatalf("unexpected route %s -> %s", result.SourceWallet, result.DestinationWallet)
	}
	if result.AmountSOL != 1.5 {
		t.Fatalf("amount=%v", result.AmountSOL)
	}
	if result.Signature != "funding-signature" || result.Slot != 100 {
		t.Fatalf("evidence signature=%q slot=%d", result.Signature, result.Slot)
	}
	if !result.ObservedAt.Equal(time.Unix(oldTime, 0).UTC()) {
		t.Fatalf("observed_at=%s", result.ObservedAt)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.pageRequests) != 2 {
		t.Fatalf("page requests=%d", len(fixture.pageRequests))
	}
	if before, _ := fixture.pageRequests[1]["before"].(string); before != "funding-signature" {
		t.Fatalf("second cursor=%q", before)
	}
}

func TestFindActorFundingOriginDoesNotCallBoundedWindowInitial(t *testing.T) {
	resetSolanaRPCCachesForTest()
	wallet := "Wallet222222222222222222222222222222222222"
	funder := "Funder222222222222222222222222222222222222"
	blockTime := int64(1700000000)
	fixture := &actorFundingRPCFixture{
		pages: map[string][]SolanaSignatureInfo{
			"": {{Signature: "bounded-funding", Slot: 300, BlockTime: &blockTime}},
		},
		transactions: map[string]map[string]any{
			"bounded-funding": fundingTransaction(wallet, funder, 500_000_000, blockTime, true, "transfer"),
		},
	}
	server := fixture.server(t)
	defer server.Close()

	result, err := FindActorFundingOrigin(context.Background(), server.URL, wallet, ActorFundingOriginOptions{
		PageSize: 1, MaxPages: 1, OldestTransactionsToParse: 5,
	})
	if err != nil {
		t.Fatalf("find funding origin: %v", err)
	}
	if result.HistoryComplete {
		t.Fatal("bounded history must not be complete")
	}
	if result.Status != "oldest_funding_within_scanned_window" {
		t.Fatalf("status=%q", result.Status)
	}
	if result.VerificationStatus != "verified" {
		t.Fatalf("the transfer relation itself should remain verified, got %q", result.VerificationStatus)
	}
}

func TestFindActorFundingOriginRequiresSourceSignerForVerified(t *testing.T) {
	resetSolanaRPCCachesForTest()
	wallet := "Wallet333333333333333333333333333333333333"
	funder := "Funder333333333333333333333333333333333333"
	blockTime := int64(1700000000)
	fixture := &actorFundingRPCFixture{
		pages: map[string][]SolanaSignatureInfo{
			"":                {{Signature: "unsigned-source", Slot: 400, BlockTime: &blockTime}},
			"unsigned-source": {},
		},
		transactions: map[string]map[string]any{
			"unsigned-source": fundingTransaction(wallet, funder, 700_000_000, blockTime, false, "createAccount"),
		},
	}
	server := fixture.server(t)
	defer server.Close()

	result, err := FindActorFundingOrigin(context.Background(), server.URL, wallet, ActorFundingOriginOptions{
		PageSize: 1, MaxPages: 2, OldestTransactionsToParse: 5,
	})
	if err != nil {
		t.Fatalf("find funding origin: %v", err)
	}
	if result.VerificationStatus != "observed" {
		t.Fatalf("verification=%q", result.VerificationStatus)
	}
}

func TestActorFundingOriginEvidence(t *testing.T) {
	origin := ActorFundingOrigin{
		Wallet:             "Wallet444444444444444444444444444444444444",
		Status:             "initial_funding_observed",
		HistoryComplete:    true,
		SourceWallet:       "Funder444444444444444444444444444444444444",
		DestinationWallet:  "Wallet444444444444444444444444444444444444",
		AmountSOL:          2.25,
		Signature:          "funding-evidence-signature",
		Slot:               500,
		ObservedAt:         time.Unix(1700000000, 0).UTC(),
		Program:            "system",
		InstructionType:    "transfer",
		VerificationStatus: "verified",
		TrailStatus:        "source_wallet_observed",
		IdentityScope:      "onchain_wallet_only",
	}
	evidence, ok := ActorFundingOriginEvidence(origin, "solana-mainnet")
	if !ok {
		t.Fatal("expected evidence record")
	}
	if evidence.Relation != "initial_funding_in" || evidence.CounterpartID != origin.SourceWallet {
		t.Fatalf("evidence=%#v", evidence)
	}
	if evidence.Metadata["source_wallet"] != origin.SourceWallet || evidence.Metadata["destination_wallet"] != origin.DestinationWallet {
		t.Fatalf("metadata=%#v", evidence.Metadata)
	}
}

func fundingTransaction(wallet, funder string, lamports, blockTime int64, sourceSigner bool, kind string) map[string]any {
	info := map[string]any{"source": funder, "lamports": lamports}
	if kind == "createAccount" {
		info["newAccount"] = wallet
	} else {
		info["destination"] = wallet
	}
	return map[string]any{
		"blockTime": blockTime,
		"meta":      map[string]any{"err": nil, "innerInstructions": []any{}},
		"transaction": map[string]any{"message": map[string]any{
			"accountKeys": []any{
				map[string]any{"pubkey": funder, "signer": sourceSigner},
				map[string]any{"pubkey": wallet, "signer": false},
			},
			"instructions": []any{map[string]any{
				"program": "system",
				"parsed":  map[string]any{"type": kind, "info": info},
			}},
		}},
	}
}

func outgoingTransaction(wallet, destination string, blockTime int64) map[string]any {
	return map[string]any{
		"blockTime": blockTime,
		"meta":      map[string]any{"err": nil, "innerInstructions": []any{}},
		"transaction": map[string]any{"message": map[string]any{
			"accountKeys": []any{
				map[string]any{"pubkey": wallet, "signer": true},
				map[string]any{"pubkey": destination, "signer": false},
			},
			"instructions": []any{map[string]any{
				"program": "system",
				"parsed": map[string]any{"type": "transfer", "info": map[string]any{
					"source": wallet, "destination": destination, "lamports": 10_000,
				}},
			}},
		}},
	}
}
