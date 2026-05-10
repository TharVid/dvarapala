package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/tharvid/dvarapala/internal/ui"
)

func cmdUI(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	var (
		listen    string
		auditPath string
		backlog   int
	)
	fs.StringVar(&listen, "listen", "127.0.0.1:9090", "local address to bind the UI on")
	fs.StringVar(&auditPath, "audit", defaultAuditPath(), "audit log path to tail")
	fs.IntVar(&backlog, "backlog", 500, "events to load on initial page render")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: dvarapala ui [flags]

Serve a read-only web view of the audit log on a local HTTP port.
Live event stream via Server-Sent Events; click any row to inspect
the full request / response payload, decision, and rule.

The UI is read-only: there is no API to modify policy or kill
daemons. Same trust posture as `+"`dvarapala logs -f`"+` — bind
defaults to 127.0.0.1 so it isn't reachable off-host.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), `
Examples:
  dvarapala ui
  dvarapala ui --listen 127.0.0.1:9091
  dvarapala ui --audit /tmp/custom-audit.jsonl
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	return ui.Run(ctx, ui.Options{
		AuditPath:    expandHome(auditPath),
		Listen:       listen,
		BacklogLines: backlog,
	})
}
