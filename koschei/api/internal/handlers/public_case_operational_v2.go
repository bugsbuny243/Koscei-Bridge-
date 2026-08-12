package handlers

import (
	"net/http"
	"strconv"
	"strings"
)

// PublicCaseOperationalPageV2 keeps the immutable bundle as the source of truth
// but projects the registry states without collapsing six different meanings
// into one "missing" number. Public visibility is independently re-authorized
// on every request through the publication ledger-backed exposure loader.
func (h *Handler) PublicCaseOperationalPageV2(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DB == nil {
		http.NotFound(w, r)
		return
	}
	caseRef := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/case/"))
	if !publicDossierCaseRefPattern.MatchString(caseRef) {
		http.NotFound(w, r)
		return
	}
	record, err := loadPublicExposureRecord(r.Context(), h.DB, caseRef)
	if err != nil {
		if publicExposureNotAuthorized(err) {
			http.NotFound(w, r)
			return
		}
		if publicExposureIntegrityFailed(err) {
			http.Error(w, "public case integrity check failed", http.StatusConflict)
			return
		}
		http.Error(w, "public case unavailable", http.StatusServiceUnavailable)
		return
	}
	bundle := record.Bundle

	technical := buildPublicCasePageData(bundle, record.Title, record.Summary, record.Featured, record.PublishedAt)
	applyPublicCaseRegistryProjection(&technical, bundle)
	data := buildPublicCaseOperationalPageData(technical)
	data.Evidence = publicCaseOperationalEvidenceRows(bundle.EvidenceLog, 5)
	data.VanityClusters = publicCaseOperationalVanityClusters(bundle.CrossTokenConnections)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	applyPublicExposureHeaders(w, record)
	w.Header().Set("X-Robots-Tag", "index, follow")
	if err := publicCaseOperationalHTML.Execute(w, data); err != nil {
		http.Error(w, "public case operational render failed", http.StatusInternalServerError)
	}
}

func applyPublicCaseRegistryProjection(data *publicCasePageData, bundle dossierBundle) {
	if data == nil {
		return
	}
	rowByID := map[string]map[string]any{}
	for _, raw := range dossierSlice(dossierMap(bundle.VerdictCard)["signal_rows"]) {
		row := dossierMap(raw)
		rowByID[dossierString(row["id"])] = row
	}
	pass, fail, open := 0, 0, 0
	for index := range data.Signals {
		signal := &data.Signals[index]
		state := normalizeSignalState(signal.State)
		signal.State = state
		signal.StateClass = publicCaseStateClass(state)
		limitations := dossierStrings(rowByID[signal.ID]["limitations"])
		if len(limitations) > 0 {
			limitation := strings.Join(limitations, " ")
			if strings.TrimSpace(signal.Summary) == "" {
				signal.Summary = limitation
			} else {
				signal.Summary += " · " + limitation
			}
		}
		switch signalStateGroup(state) {
		case signalGroupEvidence, signalGroupClosed:
			signal.AcceptanceStatus = "pass"
			pass++
		case signalGroupBlocked:
			signal.AcceptanceStatus = "fail"
			fail++
		default:
			signal.AcceptanceStatus = "not_investigated"
			open++
		}
	}
	data.Acceptance.Pass = pass
	data.Acceptance.Fail = fail
	data.Acceptance.NotInvestigated = open
	if fail > 0 || open > 0 {
		data.Acceptance.Status = "evidence_pending"
		data.Acceptance.Class = "unknown"
	} else {
		data.Acceptance.Status = "complete"
		data.Acceptance.Class = "verified"
	}
	counts := publicCaseStateCounts(data.Signals)
	openRows := counts[signalStateWindowOpen] + counts[signalStatePending] + counts[signalStateNotInvestigated]
	blockedRows := counts[signalStateUnavailable] + counts[signalStateUnknown]
	data.Metrics = []publicCaseMetricView{
		{Label: "Evidence log", Value: strconv.Itoa(len(data.Evidence)), Note: "Son görünür kanıt satırları", Class: "cyan"},
		{Label: "Verified", Value: strconv.Itoa(counts[signalStateVerified]), Note: "Doğrudan doğrulanmış", Class: "green"},
		{Label: "Observed", Value: strconv.Itoa(counts[signalStateObserved]), Note: "Gözlenen kanıt", Class: "cyan"},
		{Label: "Açık iş", Value: strconv.Itoa(openRows), Note: "Worker/pencere tamamlanmadı", Class: "amber"},
		{Label: "Uygulanamaz", Value: strconv.Itoa(counts[signalStateNotApplicable]), Note: "Bu hedefe geçerli değil", Class: "violet"},
		{Label: "Kaynak yok", Value: strconv.Itoa(blockedRows), Note: "Unavailable veya unknown", Class: "amber"},
		{Label: "Inferred", Value: strconv.Itoa(counts[signalStateInferred]), Note: "Watch-only; grade değiştirmez", Class: "violet"},
	}
}
