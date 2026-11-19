//go:build linux

// Package xattr is a minimal wrapper around the Linux extended-attribute
// syscalls.
//
// It exists so the rest of layerclue does not pull a third-party module for
// four syscalls, and so the binary stays statically linked and CGO-free.
package xattr

import "syscall"

// Get reads the named attribute of path. The second result reports whether
// the attribute exists and is non-empty.
func Get(path, name string) ([]byte, bool) {
	size, err := syscall.Getxattr(path, name, nil)
	if err != nil || size <= 0 {
		return nil, false
	}
	buf := make([]byte, size)
	n, err := syscall.Getxattr(path, name, buf)
	if err != nil || n <= 0 {
		return nil, false
	}
	return buf[:n], true
}

// Has reports whether path carries the named attribute.
func Has(path, name string) bool {
	_, ok := Get(path, name)
	return ok
}

// Set writes the named attribute. It is exported for tests and for tooling
// that builds synthetic fixtures; layerclue itself never writes to evidence.
func Set(path, name string, value []byte) error {
	return syscall.Setxattr(path, name, value, 0)
}
