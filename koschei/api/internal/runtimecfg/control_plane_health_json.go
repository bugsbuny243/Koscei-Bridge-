package runtimecfg

import "encoding/json"

type controlPlaneHealthPublicJSON struct {
	Version       string `json:"version"`
	OK            bool   `json:"ok"`
	Controls      int    `json:"controls"`
	Active        int    `json:"active"`
	Disabled      int    `json:"disabled"`
	Defaulted     int    `json:"defaulted"`
	Shadowed      int    `json:"shadowed"`
	Misconfigured int    `json:"misconfigured"`
}

func (report ControlPlaneHealth) MarshalJSON() ([]byte, error) {
	return json.Marshal(controlPlaneHealthPublicJSON{
		Version:       report.Version,
		OK:            report.OK,
		Controls:      report.Controls,
		Active:        report.Active,
		Disabled:      report.Disabled,
		Defaulted:     report.Defaulted,
		Shadowed:      report.Shadowed,
		Misconfigured: report.Misconfigured,
	})
}
