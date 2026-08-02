package handlers

import (
	"bytes"
	"strings"
	"testing"
)

func TestDossierHTMLIsStableAndContainsNoInlineExecutionSurface(t *testing.T) {
	data := dossierPageData{
		Bundle: dossierBundle{
			dossierBody: dossierBody{CaseRef: "KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			BundleHash:  "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		},
		Actor:    true,
		Sections: []dossierPageSection{{Title: "Evidence", Content: `{"ok":true}`}},
	}
	var output bytes.Buffer
	if err := dossierHTML.Execute(&output, data); err != nil {
		t.Fatalf("execute dossier template: %v", err)
	}
	body := strings.ToLower(output.String())
	for _, forbidden := range []string{"<style", "<script", "javascript:", " onclick=", " style="} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("stable dossier template contains forbidden inline surface %q", forbidden)
		}
	}
	if !strings.Contains(body, `href="/css/dossier-print.css?v=1"`) {
		t.Fatal("stable dossier stylesheet link is missing")
	}
	if !strings.Contains(body, strings.ToLower(data.Bundle.CaseRef)) || !strings.Contains(body, strings.ToLower(data.Bundle.BundleHash)) {
		t.Fatal("dossier identity fields are missing")
	}
}
