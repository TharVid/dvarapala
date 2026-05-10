// Command check-gitleaks is a tiny ad-hoc diagnostic that prints what
// gitleaks finds in a given file. Used to debug detector mismatches
// between dvarapala test (whole-line scan) and dvarapala wrap
// (per-JSON-string scan).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/tharvid/dvarapala/internal/detectors/secrets"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: check-gitleaks <file>")
		os.Exit(1)
	}
	d, err := secrets.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		os.Exit(1)
	}
	content, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}

	fmt.Println("=== gitleaks findings on RAW content ===")
	hits, _ := d.Detect(context.Background(), string(content))
	if len(hits) == 0 {
		fmt.Println("  (none)")
	}
	for _, h := range hits {
		fmt.Printf("  rule=%-30s start=%d end=%d match=%q\n", h.RuleID, h.Start, h.End, h.Match)
	}

	jsonForm, _ := json.Marshal(string(content))
	fmt.Println()
	fmt.Println("=== gitleaks findings on JSON-encoded content (quoted+escaped) ===")
	hits2, _ := d.Detect(context.Background(), string(jsonForm))
	if len(hits2) == 0 {
		fmt.Println("  (none)")
	}
	for _, h := range hits2 {
		fmt.Printf("  rule=%-30s start=%d end=%d match=%q\n", h.RuleID, h.Start, h.End, h.Match)
	}
}
