package executionproof

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ForkCanonicalityVerifier is checked after the isolated fork execution and
// immediately before any signing side effect. It closes the reorg/staleness
// window between simulation and authorization.
type ForkCanonicalityVerifier interface {
	VerifyCanonical(ctx context.Context, chainID uint64, referenceBlock uint64, referenceHash string) error
}

type RPCForkCanonicalityVerifier struct {
	RPCURL     string
	MaxHeadLag uint64
	Timeout    time.Duration
}

func (v RPCForkCanonicalityVerifier) VerifyCanonical(ctx context.Context, chainID uint64, referenceBlock uint64, referenceHash string) error {
	// MaxHeadLag is an authorization policy, not an optional optimization.
	// A zero value must fail closed; otherwise omitted configuration silently
	// turns the freshness gate into an unlimited-age acceptance rule.
	if strings.TrimSpace(v.RPCURL) == "" || chainID == 0 || referenceBlock == 0 || !validHex32(referenceHash) || v.MaxHeadLag == 0 {
		return errors.New("invalid canonicality verifier request")
	}
	client := &evmRPCClient{url: v.RPCURL, http: &http.Client{Timeout: durationOr(v.Timeout, 5*time.Second)}}
	observedChain, err := client.chainID(ctx)
	if err != nil || observedChain != chainID {
		return errors.New("canonical chain id mismatch")
	}
	observedHash, err := client.blockHash(ctx, referenceBlock)
	if err != nil || !equalHex32(observedHash, referenceHash) {
		return errors.New("reference block is no longer canonical")
	}
	var headHex string
	if err := client.call(ctx, "eth_blockNumber", []any{}, &headHex); err != nil {
		return fmt.Errorf("read canonical head: %w", err)
	}
	headHex = strings.TrimPrefix(strings.TrimSpace(headHex), "0x")
	head, err := strconv.ParseUint(headHex, 16, 64)
	if err != nil || head < referenceBlock {
		return errors.New("invalid canonical head")
	}
	if head-referenceBlock > v.MaxHeadLag {
		return errors.New("fork reference block is stale")
	}
	return nil
}
