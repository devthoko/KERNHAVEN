package storage

import (
	"encoding/json"
	"strings"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// parseSMART reads `smartctl --json=c -H -A -i` output. smartctl reports
// problems through its exit status bit mask and its messages, so the JSON is
// parsed even when the command "failed".
func parseSMART(out []byte, exitCode int) agentproto.SMART {
	var doc struct {
		Smartctl struct {
			Messages []struct {
				String   string `json:"string"`
				Severity string `json:"severity"`
			} `json:"messages"`
		} `json:"smartctl"`
		SmartStatus *struct {
			Passed bool `json:"passed"`
		} `json:"smart_status"`
		Temperature *struct {
			Current int `json:"current"`
		} `json:"temperature"`
		PowerOnTime *struct {
			Hours int `json:"hours"`
		} `json:"power_on_time"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return agentproto.SMART{Message: "smartctl output could not be read"}
	}
	var msgs []string
	for _, m := range doc.Smartctl.Messages {
		if m.String != "" {
			msgs = append(msgs, m.String)
		}
	}
	// Bits 0 and 1: command line or device open failed.
	if exitCode&0b11 != 0 || doc.SmartStatus == nil {
		msg := strings.Join(msgs, "; ")
		if msg == "" {
			msg = "SMART is not supported by this device"
		}
		return agentproto.SMART{Message: msg}
	}
	s := agentproto.SMART{Available: true}
	passed := doc.SmartStatus.Passed
	s.Passed = &passed
	if doc.Temperature != nil {
		s.TemperatureC = doc.Temperature.Current
	}
	if doc.PowerOnTime != nil {
		s.PowerOnHours = doc.PowerOnTime.Hours
	}
	if !passed {
		s.Message = "the disk reports a failing health self-assessment; back up its data"
	}
	return s
}
