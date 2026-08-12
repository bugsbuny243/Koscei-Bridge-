package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"
)

func paddleTestSignature(timestamp int64, raw []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	_, _ = mac.Write([]byte(":"))
	_, _ = mac.Write(raw)
	return "ts=" + strconv.FormatInt(timestamp, 10) + ";h1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyPaddleWebhookSignatureAcceptsExactRawBody(t *testing.T) {
	now := time.Date(2026, 8, 12, 17, 0, 0, 0, time.UTC)
	raw := []byte(`{"event_type":"transaction.completed","data":{"id":"txn_1"}}`)
	header := paddleTestSignature(now.Unix(), raw, "secret")
	if err := verifyPaddleWebhookSignature(header, raw, "secret", now); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifyPaddleWebhookSignatureRejectsBodyMutation(t *testing.T) {
	now := time.Date(2026, 8, 12, 17, 0, 0, 0, time.UTC)
	raw := []byte(`{"event_type":"transaction.completed"}`)
	header := paddleTestSignature(now.Unix(), raw, "secret")
	mutated := append(append([]byte{}, raw...), ' ')
	if err := verifyPaddleWebhookSignature(header, mutated, "secret", now); err == nil {
		t.Fatal("mutated webhook body accepted")
	}
}

func TestVerifyPaddleWebhookSignatureRejectsStaleTimestamp(t *testing.T) {
	now := time.Date(2026, 8, 12, 17, 0, 0, 0, time.UTC)
	raw := []byte(`{"event_type":"transaction.completed"}`)
	old := now.Add(-paddleWebhookTimestampWindow - time.Second)
	header := paddleTestSignature(old.Unix(), raw, "secret")
	if err := verifyPaddleWebhookSignature(header, raw, "secret", now); err == nil {
		t.Fatal("stale webhook timestamp accepted")
	}
}

func TestPaddleTransactionPriceBinding(t *testing.T) {
	var event paddleTransactionEvent
	event.Items = append(event.Items, struct {
		Price struct {
			ID string `json:"id"`
		} `json:"price"`
		PriceID string `json:"price_id"`
	}{PriceID: "pri_starter"})
	if !paddleTransactionHasPrice(event, "pri_starter") {
		t.Fatal("configured transaction price was not found")
	}
	if paddleTransactionHasPrice(event, "pri_enterprise") {
		t.Fatal("mismatched transaction price was accepted")
	}
}

func TestPlanTierAuthorizationUsesSaaSHierarchy(t *testing.T) {
	if !planTierAuthorizes("professional", "starter") {
		t.Fatal("professional should authorize starter route")
	}
	if planTierAuthorizes("starter", "professional") {
		t.Fatal("starter unexpectedly authorized professional route")
	}
	if !planTierAuthorizes("studio", "enterprise") {
		t.Fatal("enterprise compatibility alias did not authorize enterprise")
	}
	if planTierAuthorizes("holder", "starter") {
		t.Fatal("token-holder label unexpectedly authorized a SaaS route")
	}
}
