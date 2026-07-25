package http

import (
	"net/http"

	"koschei/api/internal/handlers"
)

func registerDefenseOSRoutes(mux *http.ServeMux, h *handlers.Handler) {
	mux.HandleFunc("/api/owner/defense/artifacts", requiresDB(h, ownerOnly(h, h.OwnerDefenseArtifacts)))
	mux.HandleFunc("/api/owner/defense/knowledge", requiresDB(h, ownerOnly(h, h.OwnerDefenseKnowledge)))
	mux.HandleFunc("/api/owner/defense/lab", requiresDB(h, ownerOnly(h, h.OwnerDefenseLab)))
	mux.HandleFunc("/api/owner/defense/deployment", requiresDB(h, ownerOnly(h, h.OwnerDefenseDeployment)))
	mux.HandleFunc("/api/owner/defense/source-import", requiresDB(h, ownerOnly(h, h.OwnerDefenseSourceImport)))
	mux.HandleFunc("/api/owner/defense/worker-jobs", requiresDB(h, ownerOnly(h, h.OwnerDefenseWorkerJobs)))
	mux.HandleFunc("/api/owner/defense/reproduction", requiresDB(h, ownerOnly(h, h.OwnerDefenseReproduction)))
	mux.HandleFunc("/api/owner/defense/sentinel", requiresDB(h, ownerOnly(h, h.OwnerDefenseSentinel)))
	mux.HandleFunc("/api/owner/defense/harness", requiresDB(h, ownerOnly(h, h.OwnerDefenseHarness)))
	mux.HandleFunc("/api/owner/defense/harness-execution", requiresDB(h, ownerOnly(h, h.OwnerDefenseHarnessExecution)))
	mux.HandleFunc("/api/owner/defense/harness-materialization", requiresDB(h, ownerOnly(h, h.OwnerDefenseHarnessMaterialization)))
	mux.HandleFunc("/api/owner/defense/litesvm-execution", requiresDB(h, ownerOnly(h, h.OwnerDefenseLiteSVMExecution)))
}
