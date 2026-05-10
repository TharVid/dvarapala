// Package version exposes build-time identification injected via -ldflags.
package version

import "fmt"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func String() string {
	return fmt.Sprintf("dvarapala %s (commit %s, built %s)", Version, Commit, Date)
}
