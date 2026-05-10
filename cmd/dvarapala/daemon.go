package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// daemonRecord describes one background `dvarapala proxy` instance launched
// by `dvarapala install --wrap-all`. Persisted as JSON in
// ~/.dvarapala/daemons/<name>.json so `dvarapala daemon list/stop` can find
// and manage them across shells.
type daemonRecord struct {
	Name     string `json:"name"`
	PID      int    `json:"pid"`
	Listen   string `json:"listen"`
	Upstream string `json:"upstream"`
	LogFile  string `json:"log_file"`
	Started  string `json:"started"`
}

func daemonsDir() string {
	return filepath.Join(defaultStoreDir(), "daemons")
}

func daemonRecordPath(name string) string {
	return filepath.Join(daemonsDir(), name+".json")
}

func loadDaemonRecords() ([]daemonRecord, error) {
	dir := daemonsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []daemonRecord
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var r daemonRecord
		if err := json.Unmarshal(b, &r); err != nil {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func saveDaemonRecord(r daemonRecord) error {
	if err := os.MkdirAll(daemonsDir(), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	return os.WriteFile(daemonRecordPath(r.Name), b, 0o600)
}

func deleteDaemonRecord(name string) error {
	err := os.Remove(daemonRecordPath(name))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// processAlive returns true if the given PID exists in the process table.
// Uses signal-0 which is portable across macOS and Linux.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// spawnProxy starts a `dvarapala proxy` background process detached from
// the parent shell, writes its log to ~/.dvarapala/daemons/<name>.log, and
// records the resulting PID. Returns the daemonRecord on success.
//
// On macOS / Linux the child gets a fresh setsid-style session via the
// SysProcAttr setting so it survives the parent's exit. Stdout+stderr go
// to the log file.
func spawnProxy(binary, name, upstream, listen, policyPath, auditPath string) (daemonRecord, error) {
	if err := os.MkdirAll(daemonsDir(), 0o755); err != nil {
		return daemonRecord{}, err
	}
	logPath := filepath.Join(daemonsDir(), name+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return daemonRecord{}, fmt.Errorf("open log %s: %w", logPath, err)
	}

	args := []string{
		"proxy",
		"--upstream", upstream,
		"--listen", listen,
		"--policy", policyPath,
		"--audit", auditPath,
	}
	cmd := exec.Command(binary, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = newSessionSysProcAttr()
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return daemonRecord{}, fmt.Errorf("start proxy: %w", err)
	}
	// Capture PID BEFORE Release — Release zeroes the Process struct.
	pid := cmd.Process.Pid
	// Detach: Release the in-process resources without killing the child.
	// The child has its own session via Setsid (or DETACHED_PROCESS on
	// Windows) and will outlive us as an orphan reaped by init.
	_ = cmd.Process.Release()
	_ = logFile.Close()

	rec := daemonRecord{
		Name:     name,
		PID:      pid,
		Listen:   listen,
		Upstream: upstream,
		LogFile:  logPath,
		Started:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := saveDaemonRecord(rec); err != nil {
		return rec, fmt.Errorf("save record: %w", err)
	}
	return rec, nil
}

// stopDaemon sends SIGTERM to the recorded PID. Returns whether the
// process was alive at signal time. The record is KEPT (not deleted) so
// `dvarapala install --wrap-all` can re-spawn from it later. To delete a
// record explicitly use `dvarapala daemon remove NAME`.
func stopDaemon(rec daemonRecord) (alive bool, err error) {
	if !processAlive(rec.PID) {
		return false, nil
	}
	p, err := os.FindProcess(rec.PID)
	if err != nil {
		return true, err
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		return true, err
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(rec.PID) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if processAlive(rec.PID) {
		_ = p.Signal(syscall.SIGKILL)
	}
	return true, nil
}

// findDaemonRecord returns the saved record for name, if any.
func findDaemonRecord(name string) (daemonRecord, bool) {
	recs, err := loadDaemonRecords()
	if err != nil {
		return daemonRecord{}, false
	}
	for _, r := range recs {
		if r.Name == name {
			return r, true
		}
	}
	return daemonRecord{}, false
}

// pickFreePort returns an unused TCP port we can bind to. We don't keep it
// reserved — there's a tiny race window between this and the proxy
// actually binding, but in practice it's fine on a developer machine.
// The starting hint is 18080, incrementing.
func pickFreePort(startHint int, used map[int]bool) (int, error) {
	for p := startHint; p < startHint+1000; p++ {
		if used[p] {
			continue
		}
		if portFree(p) {
			used[p] = true
			return p, nil
		}
	}
	return 0, errors.New("no free port found in range")
}

// cmdDaemon — `dvarapala daemon list | stop NAME | stop-all | remove NAME | clean`.
func cmdDaemon(_ context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: dvarapala daemon list | stop NAME | stop-all | remove NAME | clean")
	}
	switch args[0] {
	case "list":
		return cmdDaemonList()
	case "stop":
		if len(args) != 2 {
			return errors.New("usage: dvarapala daemon stop NAME")
		}
		return cmdDaemonStop(args[1])
	case "stop-all":
		return cmdDaemonStopAll()
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: dvarapala daemon remove NAME")
		}
		return cmdDaemonRemove(args[1])
	case "clean":
		return cmdDaemonClean()
	default:
		return fmt.Errorf("unknown daemon subcommand %q", args[0])
	}
}

// cmdDaemonRemove — kill (if alive) and delete the record for NAME.
func cmdDaemonRemove(name string) error {
	rec, ok := findDaemonRecord(name)
	if !ok {
		return fmt.Errorf("no daemon record %q", name)
	}
	if alive, err := stopDaemon(rec); err == nil && alive {
		fmt.Fprintf(os.Stderr, "stopped %s (pid %d)\n", rec.Name, rec.PID)
	}
	if err := deleteDaemonRecord(name); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "removed daemon record %q\n", name)
	return nil
}

// cmdDaemonClean — delete records whose recorded process is no longer alive.
func cmdDaemonClean() error {
	recs, err := loadDaemonRecords()
	if err != nil {
		return err
	}
	cleaned := 0
	for _, r := range recs {
		if processAlive(r.PID) {
			continue
		}
		if err := deleteDaemonRecord(r.Name); err == nil {
			fmt.Fprintf(os.Stderr, "  removed stale record %q (pid %d)\n", r.Name, r.PID)
			cleaned++
		}
	}
	if cleaned == 0 {
		fmt.Fprintln(os.Stderr, "no stale records")
	}
	return nil
}

func cmdDaemonList() error {
	recs, err := loadDaemonRecords()
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		fmt.Fprintln(os.Stderr, "no daemons registered")
		return nil
	}
	fmt.Fprintf(os.Stderr, "%-20s  %-7s  %-22s  %-40s  %s\n", "NAME", "PID", "LISTEN", "UPSTREAM", "STATUS")
	for _, r := range recs {
		status := "running"
		if !processAlive(r.PID) {
			status = "DEAD (record stale)"
		}
		fmt.Fprintf(os.Stderr, "%-20s  %-7d  %-22s  %-40s  %s\n",
			r.Name, r.PID, r.Listen, truncate(r.Upstream, 40), status)
	}
	return nil
}

func cmdDaemonStop(name string) error {
	recs, err := loadDaemonRecords()
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.Name == name {
			alive, err := stopDaemon(r)
			if err != nil {
				return err
			}
			if alive {
				fmt.Fprintf(os.Stderr, "stopped %s (pid %d)\n", r.Name, r.PID)
			} else {
				fmt.Fprintf(os.Stderr, "%s already stopped (cleared stale record)\n", r.Name)
			}
			return nil
		}
	}
	return fmt.Errorf("no daemon named %q", name)
}

func cmdDaemonStopAll() error {
	recs, err := loadDaemonRecords()
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		fmt.Fprintln(os.Stderr, "no daemons registered")
		return nil
	}
	for _, r := range recs {
		alive, err := stopDaemon(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  failed to stop %s: %v\n", r.Name, err)
			continue
		}
		state := "stopped"
		if !alive {
			state = "already gone"
		}
		fmt.Fprintf(os.Stderr, "  %s — %s (pid %d)\n", r.Name, state, r.PID)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// portStartHint is the first port we try when picking a free local port for
// a spawned proxy. Picked above the typical user-app range to avoid common
// dev-server collisions.
func portStartHint() int { return 18080 }

func portFromListen(addr string) int {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		if n, err := strconv.Atoi(addr[i+1:]); err == nil {
			return n
		}
	}
	return 0
}
