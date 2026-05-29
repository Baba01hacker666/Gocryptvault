//go:build linux
// +build linux

package main

import (
	"log"

	"golang.org/x/sys/unix"
)

func InitSecurity() {
	// Disable core dumps
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		log.Printf("Failed to disable core dumps: %v", err)
	}
}
