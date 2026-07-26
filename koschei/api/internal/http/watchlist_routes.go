package http

import (
	"net/http"

	"koschei/api/internal/handlers"
	"koschei/api/internal/workerwake"
)

func registerWatchlistRoutes(mux *http.ServeMux, h *handlers.Handler, proMetered routeGate, enterprise routeGate) {
	mux.HandleFunc("/api/public/token/status", method(http.MethodGet, h.PublicTokenStatus))
	mux.HandleFunc("/api/public/token/readiness", method(http.MethodGet, h.PublicTokenLaunchReadiness))
	mux.HandleFunc("/api/public/scan-history", method(http.MethodGet, h.PublicScanHistory))
	mux.HandleFunc("/api/public/transaction-simulate", method(http.MethodPost, h.PublicTransactionSimulate))

	mux.HandleFunc("/api/auth/wallet/challenge", requiresDB(h, handlers.RequireAuth(method(http.MethodPost, h.CreateWalletChallenge))))
	mux.HandleFunc("/api/auth/wallet/verify", requiresDB(h, handlers.RequireAuth(method(http.MethodPost, h.VerifyWalletChallenge))))
	mux.HandleFunc("/api/auth/wallet/status", requiresDB(h, handlers.RequireAuth(method(http.MethodGet, h.WalletLinkStatus))))
	mux.HandleFunc("/api/auth/wallet/unlink", requiresDB(h, handlers.RequireAuth(method(http.MethodPost, h.UnlinkWallet))))
	mux.HandleFunc("/api/auth/token-access", requiresDB(h, handlers.RequireAuth(method(http.MethodGet, h.TokenAccessStatus))))
	mux.HandleFunc("/api/auth/premium-access", requiresDB(h, handlers.RequireAuth(method(http.MethodGet, h.PremiumAccessStatus))))

	// Watchlist alerts enqueue webhook deliveries through a PostgreSQL AFTER
	// INSERT trigger. Wake after the request handler returns, which is after the
	// transaction commits and the trigger-created delivery rows are visible.
	mux.HandleFunc("/api/watchlist", requiresDB(h, proMetered(wakeWebhookDeliveryAfterWatchlistPost(h.WatchlistCollection))))
	mux.HandleFunc("/api/watchlist/refresh", requiresDB(h, proMetered(wakeWebhookDeliveryAfterWatchlistPost(method(http.MethodPost, h.WatchlistRefresh)))))
	mux.HandleFunc("/api/watchlist/alerts", requiresDB(h, proMetered(h.WatchlistAlerts)))
	mux.HandleFunc("/api/watchlist/", requiresDB(h, proMetered(wakeWebhookDeliveryAfterWatchlistPost(h.WatchlistItem))))

	// Webhook management requires Enterprise eligibility but does not consume a
	// scan unit. The scans that produce webhook events are metered separately.
	mux.HandleFunc("/api/webhooks/security-alerts", requiresDB(h, enterprise(h.SecurityAlertWebhookSubscription)))
	mux.HandleFunc("/api/webhooks/deliveries", requiresDB(h, enterprise(h.WebhookDeliveries)))
	mux.HandleFunc("/api/webhooks/deliveries/", requiresDB(h, enterprise(h.WebhookDeliveryItem)))
	mux.HandleFunc("/api/webhooks", requiresDB(h, enterprise(h.WebhookEndpoints)))
	mux.HandleFunc("/api/webhooks/", requiresDB(h, enterprise(h.WebhookEndpointItem)))
}

func wakeWebhookDeliveryAfterWatchlistPost(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(w, r)
		if r.Method == http.MethodPost {
			workerwake.Signal(workerwake.WebhookDelivery)
		}
	}
}
