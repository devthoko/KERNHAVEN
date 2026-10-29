package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
)

// runAuditCheck implements `kernhaven-core audit-check EXPORT [OLDER]`
// (M17, TH-52): it verifies an exported audit log and, given an older full
// export, that the log was neither truncated nor rewritten in between. It
// needs no configuration and can run on any machine.
func runAuditCheck(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || len(args) > 2 {
		fmt.Fprintln(stderr, "usage: kernhaven-core audit-check EXPORT.jsonl [OLDER-EXPORT.jsonl]")
		return exitConfig
	}
	check := func(path string) (audit.ExportSummary, error) {
		f, err := os.Open(path)
		if err != nil {
			return audit.ExportSummary{}, err
		}
		defer f.Close()
		return audit.CheckExport(f)
	}
	s, err := check(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", args[0], err)
		return exitRuntime
	}
	if len(args) == 2 {
		old, err := check(args[1])
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", args[1], err)
			return exitRuntime
		}
		f, err := os.Open(args[0])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		defer f.Close()
		if err := audit.Continues(old, f); err != nil {
			fmt.Fprintf(stderr, "%s does not continue %s: %v\n", args[0], args[1], err)
			return exitRuntime
		}
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s)
	return exitOK
}
