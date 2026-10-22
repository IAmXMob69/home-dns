// dns-probe: send one DNS A query. Exit 0 if a nameserver actually answers.
//
// Go port of ~/pihole/dns-probe.py with identical args, output and exit codes:
//
//	dns-probe [--dot|--doh] [host] [server] [server_name]
//
// Pi-hole block responses (0.0.0.0 / ::) are labeled BLOCKED but still count
// as a successful connectivity probe (exit 0).
package main

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"pihole/go/internal/conf"
	"pihole/go/internal/dnswire"
	"pihole/go/internal/py"
)

// defaultServerName is the TLS name for --dot/--doh when none is given:
// DOT_AUTH_NAME (env or .env), else pihole.lan (the self-signed cert).
func defaultServerName() string {
	if conf.Set("DOT_AUTH_NAME") {
		return conf.Get("DOT_AUTH_NAME", "")
	}
	return "pihole.lan"
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(argv []string, stdout, stderr io.Writer) int {
	rc, err := probe(argv, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "DNS probe failed: %s\n", py.ErrStr(err))
		return 1
	}
	return rc
}

type result struct {
	data []byte
}

func probe(argv []string, stdout io.Writer) (int, error) {
	args := []string{}
	for _, a := range argv {
		if a != "--" {
			args = append(args, a)
		}
	}
	mode := "plain"
	if len(args) > 0 && (args[0] == "--dot" || args[0] == "--doh") {
		mode = args[0][2:]
		args = args[1:]
	}
	host, server, serverName := "example.com", "127.0.0.1", defaultServerName()
	if len(args) > 0 {
		host = args[0]
	}
	if len(args) > 1 {
		server = args[1]
	}
	if len(args) > 2 {
		serverName = args[2]
	}
	msg, err := dnswire.BuildQuery(host, 1)
	if err != nil {
		return 1, err
	}
	var data []byte
	switch mode {
	case "dot":
		data, err = queryDoT(msg, server, serverName, 5*time.Second)
	case "doh":
		data, err = queryDoH(msg, server, serverName, 5)
	default:
		data, err = queryUDP(msg, server, 3*time.Second)
	}
	if err != nil {
		return 1, err
	}
	rcode, ancount, err := dnswire.ParseHeader(data)
	if err != nil {
		return 1, err
	}
	var addrs []string
	if ancount > 0 {
		if addrs, err = dnswire.ParseAnswers(data); err != nil {
			return 1, err
		}
	}
	fmt.Fprint(stdout, FormatLine(mode, server, host, rcode, ancount, addrs, len(data)))
	if blocked(addrs) {
		fmt.Fprintln(stdout, "BLOCKED")
	}
	if rcode == 0 || rcode == 3 {
		return 0, nil
	}
	return 1, nil
}

func blocked(addrs []string) bool {
	for _, a := range addrs {
		if dnswire.IsBlockAddr(a) {
			return true
		}
	}
	return false
}

// FormatLine renders the key=value line update-pihole.sh and friends parse.
func FormatLine(mode, server, host string, rcode, ancount int, addrs []string, size int) string {
	addrS := "-"
	if len(addrs) > 0 {
		addrS = strings.Join(addrs, ",")
	}
	status := "fail"
	switch {
	case blocked(addrs):
		status = "BLOCKED"
	case rcode == 0 || rcode == 3:
		status = "ok"
	}
	return fmt.Sprintf("mode=%s server=%s host=%s rcode=%d answers=%d addrs=%s status=%s bytes=%d\n",
		mode, server, host, rcode, ancount, addrS, status, size)
}

func queryUDP(msg []byte, server string, timeout time.Duration) ([]byte, error) {
	raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.WriteToUDP(msg, raddr); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func readFull(c net.Conn, n int, timeout time.Duration) ([]byte, error) {
	buf := make([]byte, n)
	got := 0
	for got < n {
		_ = c.SetReadDeadline(time.Now().Add(timeout))
		m, err := c.Read(buf[got:])
		got += m
		if err != nil {
			if errors.Is(err, io.EOF) && got < n {
				return nil, errors.New("connection closed")
			}
			if got < n {
				return nil, err
			}
		}
	}
	return buf, nil
}

func queryDoT(msg []byte, server, serverName string, timeout time.Duration) ([]byte, error) {
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(server, "853"), timeout)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil {
		return nil, err
	}
	wire := binary.BigEndian.AppendUint16(nil, uint16(len(msg)))
	wire = append(wire, msg...)
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	hdr, err := readFull(conn, 2, timeout)
	if err != nil {
		return nil, err
	}
	return readFull(conn, int(binary.BigEndian.Uint16(hdr)), timeout)
}

// queryDoH shells out to curl like the Python version (dnsdist DoH is HTTP/2).
func queryDoH(msg []byte, server, serverName string, timeoutSec int) ([]byte, error) {
	fh, err := os.CreateTemp("", "tmp*.dns")
	if err != nil {
		return nil, err
	}
	defer os.Remove(fh.Name())
	if _, err := fh.Write(msg); err != nil {
		fh.Close()
		return nil, err
	}
	fh.Close()
	cmd := exec.Command("curl", "-sS", "--http2", "--max-time", strconv.Itoa(timeoutSec),
		"--resolve", fmt.Sprintf("%s:8443:%s", serverName, server),
		"-H", "Content-Type: application/dns-message",
		"-H", "Accept: application/dns-message",
		"--data-binary", "@"+fh.Name(),
		fmt.Sprintf("https://%s:8443/dns-query", serverName))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			e := strings.TrimSpace(stderr.String())
			if e == "" {
				e = fmt.Sprintf("curl exit %d", ee.ExitCode())
			}
			return nil, errors.New(e)
		}
		if errors.Is(err, exec.ErrNotFound) {
			return nil, errors.New("[Errno 2] No such file or directory: 'curl'")
		}
		return nil, err
	}
	return out, nil
}
