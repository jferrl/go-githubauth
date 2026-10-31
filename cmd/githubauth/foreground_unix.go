//go:build darwin || linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// inForeground reports whether process pid belongs to the terminal's
// foreground job, the one a Ctrl-C at the keyboard is delivered to.
func inForeground(pid int) bool {
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		return false
	}
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return false
	}
	defer func() { _ = tty.Close() }()
	return foregroundOf(tty.Fd(), pgid)
}

// foregroundOf reports whether the terminal open on fd has process group pgid
// in the foreground. A file that is not a terminal has none.
func foregroundOf(fd uintptr, pgid int) bool {
	var pgrp int32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCGPGRP), uintptr(unsafe.Pointer(&pgrp)))
	return errno == 0 && int(pgrp) == pgid
}
