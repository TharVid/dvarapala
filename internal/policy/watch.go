package policy

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"
)

// RuleLoader returns the latest set of rules. Pulled out as an interface
// so the watcher can stay agnostic about whether the loader is parsing a
// single YAML file, walking a rules.d/ directory, fetching from a remote
// store, etc.
type RuleLoader interface {
	Load() ([]Rule, error)
}

// FileRuleLoader is the default loader used by the gateway's wrap / proxy
// / hub commands: a single path on disk parsed via the config package.
// The actual Load implementation lives in the cmd/dvarapala layer (so
// this package can stay free of yaml dependencies); FileRuleLoaderFunc
// adapts an arbitrary function to the interface.
type FileRuleLoader struct {
	Path     string
	LoadFunc func(path string) ([]Rule, error)
}

// Load parses the file at p.Path via the supplied LoadFunc.
func (p *FileRuleLoader) Load() ([]Rule, error) {
	if p.LoadFunc == nil {
		return nil, fmt.Errorf("policy: FileRuleLoader.LoadFunc is nil")
	}
	return p.LoadFunc(p.Path)
}

// Watcher polls a file's modification time at a fixed cadence and, when
// it changes, asks the loader for fresh rules and atomically swaps them
// into the engine. A bad reload (parse error, regex compile error, etc.)
// is logged to errOut but never breaks the running engine: the previous
// rules continue to evaluate traffic until a successful reload arrives.
type Watcher struct {
	Engine   *Engine
	Path     string
	Loader   RuleLoader
	Interval time.Duration // default 2s
	ErrOut   io.Writer     // default stderr; nil silences errors
}

// Watch blocks until ctx is cancelled, polling the file's mtime every
// Interval. Returns nil on graceful shutdown.
func (w *Watcher) Watch(ctx context.Context) error {
	if w.Engine == nil || w.Loader == nil || w.Path == "" {
		return fmt.Errorf("policy.Watcher: Engine, Loader, and Path are required")
	}
	interval := w.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	errOut := w.ErrOut
	if errOut == nil {
		errOut = os.Stderr
	}

	lastMtime, lastSize := w.snapshot()

	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		mtime, size := w.snapshot()
		if mtime == lastMtime && size == lastSize {
			continue
		}
		lastMtime, lastSize = mtime, size
		rules, err := w.Loader.Load()
		if err != nil {
			fmt.Fprintf(errOut, "dvarapala: policy reload skipped (%s): %v\n", w.Path, err)
			continue
		}
		if err := w.Engine.Reload(rules); err != nil {
			fmt.Fprintf(errOut, "dvarapala: policy reload skipped (%s): %v\n", w.Path, err)
			continue
		}
		fmt.Fprintf(errOut, "dvarapala: policy reloaded — %d rules now active (%s)\n", len(rules), w.Path)
	}
}

// snapshot returns the current mtime and size of the watched path. When
// the file is missing (or unreadable) we report zero values so we don't
// thrash on transient errors; once the file reappears with a real
// mtime, the change-detection logic kicks in normally.
func (w *Watcher) snapshot() (time.Time, int64) {
	info, err := os.Stat(w.Path)
	if err != nil {
		return time.Time{}, 0
	}
	return info.ModTime(), info.Size()
}
