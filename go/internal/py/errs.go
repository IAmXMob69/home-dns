package py

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// ErrStr renders common network errors the way Python's str(OSError) does,
// e.g. "timed out" or "[Errno 111] Connection refused".
func ErrStr(err error) string {
	if err == nil {
		return ""
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return "timed out"
	}
	var en syscall.Errno
	if errors.As(err, &en) {
		return fmt.Sprintf("[Errno %d] %s", int(en), pyStrerror(en))
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "[Errno -2] Name or service not known"
	}
	return err.Error()
}

func pyStrerror(e syscall.Errno) string {
	s := e.Error()
	if s == "" {
		return s
	}
	// Go lower-cases the first letter; glibc strerror capitalises it.
	if s[0] >= 'a' && s[0] <= 'z' {
		return string(s[0]-32) + s[1:]
	}
	return s
}
