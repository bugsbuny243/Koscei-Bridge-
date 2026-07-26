package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type healthBoundTestDriver struct{}

func (healthBoundTestDriver) Open(string) (driver.Conn, error) {
	return healthBoundTestConn{}, nil
}

type healthBoundTestConn struct{}

func (healthBoundTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not supported")
}
func (healthBoundTestConn) Close() error { return nil }
func (healthBoundTestConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not supported")
}
func (healthBoundTestConn) Ping(context.Context) error { return nil }
func (healthBoundTestConn) QueryContext(ctx context.Context, _ string, _ []driver.NamedValue) (driver.Rows, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestHealthBoundsDetailedRefreshWhenQueriesBlock(t *testing.T) {
	const driverName = "health_bound_refresh_test"
	sql.Register(driverName, healthBoundTestDriver{})
	db, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	previousTimeout := arvisHealthRefreshTimeout
	arvisHealthRefreshTimeout = 25 * time.Millisecond
	resetArvisHealthCache()
	t.Cleanup(func() {
		arvisHealthRefreshTimeout = previousTimeout
		resetArvisHealthCache()
	})

	h := &Handler{DB: db, DBRead: db}
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	response := httptest.NewRecorder()
	started := time.Now()
	h.Health(response, request)
	elapsed := time.Since(started)

	if elapsed > 500*time.Millisecond {
		t.Fatalf("health response took %s, want below 500ms", elapsed)
	}
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	arvis, ok := payload["arvis"].(map[string]any)
	if !ok {
		t.Fatalf("arvis payload=%#v", payload["arvis"])
	}
	if got := arvis["pipeline_status"]; got != "degraded_dependency" {
		t.Fatalf("pipeline_status=%v", got)
	}
	if got := arvis["detail_status"]; got != "degraded_timeout" {
		t.Fatalf("detail_status=%v", got)
	}
	if got := arvis["refresh_error"]; got != context.DeadlineExceeded.Error() {
		t.Fatalf("refresh_error=%v", got)
	}

	cachedRequest := httptest.NewRequest(http.MethodGet, "/health", nil)
	cachedResponse := httptest.NewRecorder()
	cachedStarted := time.Now()
	h.Health(cachedResponse, cachedRequest)
	cachedElapsed := time.Since(cachedStarted)
	if cachedElapsed > 100*time.Millisecond {
		t.Fatalf("cached health response took %s, want below 100ms", cachedElapsed)
	}
	if cachedResponse.Code != http.StatusOK {
		t.Fatalf("cached status=%d body=%s", cachedResponse.Code, cachedResponse.Body.String())
	}
}
