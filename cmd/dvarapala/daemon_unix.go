//go:build !windows

package main

import (
	"net"
	"strconv"
	"syscall"
)

// newSessionSysProcAttr returns SysProcAttr that detaches the spawned
// child into its own session so it survives the parent's exit on macOS
// and Linux (Setsid).
func newSessionSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// portFree returns true when nothing is currently bound to TCP port p on
// 127.0.0.1.
func portFree(p int) bool {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}
