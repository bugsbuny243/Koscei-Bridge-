package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	piLangProductionHost = "koschei-web3-hub-production.up.railway.app"
	piPlatformBaseURL     = "https://api.minepi.com/v2"
	piLangProductID       = "koschei-lang-test-v1"
	piLangPaymentAmount   = 0.01
)

var piPlatformHTTPClient = &http.Client{Timeout: 20 * time.Second}

type piLangPaymentRequest struct {
	PaymentID string `json:"paymentId"`
	TxID      string `json:"txid,omitempty"`
}

type piLangPaymentRecord struct {
	Identifier string                 `json:"identifier"`
	Amount     float64                `json:"amount"`
	Direction  string                 `json:"direction"`
	Network    string                 `json:"network"`
	Metadata   map[string]interface{} `json:"metadata"`
	Status     struct {
		DeveloperApproved  bool `json:"developer_approved"`
		DeveloperCompleted bool `json:"developer_completed"`
		Cancelled          bool `json:"cancelled"`
		UserCancelled      bool `json:"user_cancelled"`
	} `json:"status"`
	Transaction *struct {
		TxID string `json:"txid"`
	} `json:"transaction"`
}

// piLangHostSurface gives Koschei Lang its own root-domain surface on the
// Railway service domain without changing tradepigloball.co or its existing
// Pi validation file. Pi requires an app URL with no path component, so the
// same Go service dispatches by Host instead of creating another service.
func piLangHostSurface(next http.Handler, staticDir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isPiLangHost(r.Host) {
			next.ServeHTTP(w, r)
			return
		}

		switch r.URL.Path {
		case "/", "/index.html":
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			http.ServeFile(w, r, filepath.Join(staticDir, "lang.html"))
			return
		case "/privacy", "/privacy.html":
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			http.ServeFile(w, r, filepath.Join(staticDir, "lang-privacy.html"))
			return
		case "/terms", "/terms.html":
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			http.ServeFile(w, r, filepath.Join(staticDir, "lang-terms.html"))
			return
		case "/validation-key.txt":
			servePiLangValidationKey(w, r)
			return
		case "/api/pi/ready":
			servePiLangPaymentReadiness(w, r)
			return
		case "/api/pi/payment/approve":
			handlePiLangPaymentAction(w, r, "approve")
			return
		case "/api/pi/payment/complete":
			handlePiLangPaymentAction(w, r, "complete")
			return
		case "/api/pi/payment/cancel":
			handlePiLangPaymentAction(w, r, "cancel")
			return
		default:
			next.ServeHTTP(w, r)
		}
	})
}

func servePiLangValidationKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	key := strings.TrimSpace(os.Getenv("PI_LANG_VALIDATION_KEY"))
	if key == "" {
		http.Error(w, "Pi Lang validation key is not configured", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write([]byte(key + "\n"))
}

func servePiLangPaymentReadiness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if strings.TrimSpace(os.Getenv("PI_LANG_API_KEY")) == "" {
		w.WriteHeader(http.StatusServiceUnavailable)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"ready":false,"reason":"payment-backend-not-configured"}`))
		}
		return
	}
	if r.Method == http.MethodGet {
		_, _ = fmt.Fprintf(w, `{"ready":true,"network":"testnet","amount":%.2f}`, piLangPaymentAmount)
	}
}

func handlePiLangPaymentAction(w http.ResponseWriter, r *http.Request, action string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	apiKey := strings.TrimSpace(os.Getenv("PI_LANG_API_KEY"))
	if apiKey == "" {
		http.Error(w, "Pi payment backend is not configured", http.StatusServiceUnavailable)
		return
	}

	var input piLangPaymentRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid payment request", http.StatusBadRequest)
		return
	}
	input.PaymentID = strings.TrimSpace(input.PaymentID)
	input.TxID = strings.TrimSpace(input.TxID)
	if !safePiIdentifier(input.PaymentID) {
		http.Error(w, "invalid payment id", http.StatusBadRequest)
		return
	}
	if action == "complete" && !safePiIdentifier(input.TxID) {
		http.Error(w, "invalid transaction id", http.StatusBadRequest)
		return
	}

	payment, err := fetchPiLangPayment(apiKey, input.PaymentID)
	if err != nil {
		http.Error(w, "unable to verify Pi payment", http.StatusBadGateway)
		return
	}
	if err := validatePiLangPayment(payment, input.PaymentID); err != nil {
		http.Error(w, "payment does not match Koschei Lang test purchase", http.StatusForbidden)
		return
	}

	var payload []byte
	if action == "complete" {
		payload, _ = json.Marshal(map[string]string{"txid": input.TxID})
	}
	status, responseBody, err := callPiPlatform(apiKey, http.MethodPost, "/payments/"+input.PaymentID+"/"+action, payload)
	if err != nil {
		http.Error(w, "Pi Platform request failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(responseBody)
}

func fetchPiLangPayment(apiKey, paymentID string) (piLangPaymentRecord, error) {
	status, body, err := callPiPlatform(apiKey, http.MethodGet, "/payments/"+paymentID, nil)
	if err != nil {
		return piLangPaymentRecord{}, err
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return piLangPaymentRecord{}, fmt.Errorf("Pi payment lookup returned %d", status)
	}
	var payment piLangPaymentRecord
	if err := json.Unmarshal(body, &payment); err != nil {
		return piLangPaymentRecord{}, err
	}
	return payment, nil
}

func validatePiLangPayment(payment piLangPaymentRecord, expectedID string) error {
	if payment.Identifier != expectedID {
		return errors.New("payment identifier mismatch")
	}
	if strings.ToLower(strings.TrimSpace(payment.Direction)) != "user_to_app" {
		return errors.New("unexpected payment direction")
	}
	if math.Abs(payment.Amount-piLangPaymentAmount) > 0.000001 {
		return errors.New("unexpected payment amount")
	}
	product, _ := payment.Metadata["product"].(string)
	if product != piLangProductID {
		return errors.New("unexpected payment product")
	}
	if payment.Status.Cancelled || payment.Status.UserCancelled {
		return errors.New("payment is cancelled")
	}
	return nil
}

func callPiPlatform(apiKey, method, path string, payload []byte) (int, []byte, error) {
	var body io.Reader
	if len(payload) > 0 {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, piPlatformBaseURL+path, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Key "+apiKey)
	req.Header.Set("Accept", "application/json")
	if len(payload) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := piPlatformHTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, responseBody, nil
}

func safePiIdentifier(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func isPiLangHost(hostport string) bool {
	host := strings.ToLower(strings.TrimSpace(hostport))
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host == piLangProductionHost
}
