package http

import (
	"net/http"

	"koschei/api/internal/handlers"
)

// registerBillingRoutes intentionally registers no provider-specific billing
// endpoints. Paid product authority remains server-side entitlement state.
// A billing provider may be added here only together with its verified,
// fail-closed server-side collection and webhook contract.
func registerBillingRoutes(_ *http.ServeMux, _ *handlers.Handler) {}
