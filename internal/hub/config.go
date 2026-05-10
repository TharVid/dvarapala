// Package hub implements `dvarapala hub`: one Dvarapala process fronting
// many MCP servers (mix of stdio-spawned children and HTTP/SSE upstreams),
// with HTTP path-based routing. The same engine + detectors that gate
// stdio (cmd wrap) and single HTTP (cmd proxy) traffic also gate every
// hub-routed request, so policy is consistent across all transports.
package hub

import (
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level YAML for hub.yaml.
type Config struct {
	Listen     string                  `yaml:"listen,omitempty"`
	PolicyPath string                  `yaml:"policy,omitempty"`
	Audit      string                  `yaml:"audit,omitempty"`
	Servers    map[string]ServerConfig `yaml:"servers"`
}

// ServerConfig is one entry under hub.yaml's `servers:` map. Either
// Command (stdio child) or Upstream (HTTP) must be set; setting both is
// an error.
type ServerConfig struct {
	// Type is "stdio" or "http". If empty, inferred from the other fields.
	Type     string   `yaml:"type,omitempty"`
	Command  []string `yaml:"command,omitempty"`
	Upstream string   `yaml:"upstream,omitempty"`
	Env      []string `yaml:"env,omitempty"`
	// Per-server policy overrides land in a follow-up; the global policy
	// applies to every server today.
}

// Load reads a hub config YAML from path and validates it.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	return LoadFromReader(f)
}

// LoadFromReader parses YAML from r.
func LoadFromReader(r io.Reader) (*Config, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if len(c.Servers) == 0 {
		return errors.New("hub: at least one server is required under `servers:`")
	}
	for name, s := range c.Servers {
		if name == "" {
			return errors.New("hub: empty server name")
		}
		if len(s.Command) == 0 && s.Upstream == "" {
			return fmt.Errorf("server %q: must set either `command:` (stdio) or `upstream:` (http)", name)
		}
		if len(s.Command) > 0 && s.Upstream != "" {
			return fmt.Errorf("server %q: set exactly one of `command:` or `upstream:`, not both", name)
		}
		switch s.Type {
		case "", "stdio", "http":
			// ok
		default:
			return fmt.Errorf("server %q: type %q not in {stdio, http}", name, s.Type)
		}
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:9000"
	}
	return nil
}

// kindOf returns the resolved transport for s ("stdio" or "http").
func (s ServerConfig) kindOf() string {
	if s.Type != "" {
		return s.Type
	}
	if len(s.Command) > 0 {
		return "stdio"
	}
	return "http"
}
