//go:build windows

package main

import (
	"net"
	"strconv"
	"syscall"
)

// newSessionSysProcAttr — Windows variant: DETACHED_PROCESS so the child
// survives the parent's console closing.
func newSessionSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: 0x00000008, // DETACHED_PROCESS
	}
}

func portFree(p int) bool {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}
