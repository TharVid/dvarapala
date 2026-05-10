// Package policies bundles the default Dvarapala rule packs as an embed.FS
// so the dvarapala binary can ship them without reading from disk.
//
// The YAML files in this directory serve a dual purpose:
//  1. Human-readable documentation for users browsing the repo.
//  2. The shipped defaults compiled into the binary via go:embed.
package policies

import "embed"

//go:embed *.yaml
var FS embed.FS
