// Command dvarapala is the MCP security gateway CLI.
//
// Usage:
//
//	dvarapala wrap    --policy POLICY -- COMMAND [ARGS...]
//	dvarapala proxy   --policy POLICY --upstream URL [--listen ADDR]
//	dvarapala hub     --config CONFIG
//	dvarapala init    [--policy PATH]
//	dvarapala lint    POLICY
//	dvarapala test    POLICY --case ATTACK.json
//	dvarapala install --client claude-desktop|cursor|cline --server NAME
//	dvarapala scan    MCP_SERVER
//	dvarapala doctor
//	dvarapala version
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/tharvid/dvarapala/internal/version"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "dvarapala: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "wrap":
		return cmdWrap(ctx, rest)
	case "proxy":
		return cmdProxy(ctx, rest)
	case "hub":
		return cmdHub(ctx, rest)
	case "init":
		return cmdInit(ctx, rest)
	case "lint":
		return cmdLint(ctx, rest)
	case "test":
		return cmdTest(ctx, rest)
	case "install":
		return cmdInstall(ctx, rest)
	case "scan":
		return cmdScan(ctx, rest)
	case "doctor":
		return cmdDoctor(ctx, rest)
	case "version", "-v", "--version":
		fmt.Println(version.String())
		return nil
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q (try 'dvarapala help')", cmd)
	}
}

func printUsage() {
	fmt.Print(`Dvarapala — MCP security gateway

USAGE
  dvarapala <command> [flags]

COMMANDS
  wrap       Wrap an MCP stdio server with a security policy
  proxy      Run as an HTTP/SSE proxy in front of a remote MCP server
  hub        Run as an aggregator for multiple MCP servers
  init       Scaffold a default policy file
  lint       Validate a policy file
  test       Run an attack case against a policy
  install    Auto-install into a known MCP client (Claude Desktop, Cursor, Cline)
  scan       One-shot security scan of an MCP server
  doctor     Diagnose installation and configuration
  version    Print version info

EXAMPLES
  dvarapala init
  dvarapala wrap --policy ~/.dvarapala/policy.yaml -- npx -y @modelcontextprotocol/server-filesystem ~
  dvarapala proxy --upstream https://mcp.example.com --listen 127.0.0.1:8080
  dvarapala install --client claude-desktop --server filesystem

DOCS
  https://github.com/tharvid/dvarapala
`)
}
