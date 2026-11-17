// Package syslogsink sends batches as RFC 5424 syslog over TCP or TLS, in the layout Control Plane org logging uses
// (the fluent-bit syslog output of org external logging), so a receiver that already takes org logs parses both the same way.
package syslogsink

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/controlplane-com/cpln-audit-shipper/internal/record"
)

const (
	sdID = "cpln@0"
	bom  = "\ufeff"

	FramingNewline       = "newline"
	FramingOctetCounting = "octet-counting"
)

// AppName is the APP-NAME of each source's messages; receivers route on it.
var AppName = map[string]string{
	record.KindK8sAudit:  "mk8s-audit",
	record.KindCplnAudit: "cpln-audit",
}

type Config struct {
	Host string
	Port int
	TLS  bool
	// CAFile is a PEM bundle that replaces the system CAs, for a listener with a private CA.
	CAFile          string
	Framing         string
	Facility        int
	Severity        int
	MaxMessageBytes int
	Timeout         time.Duration
	Logger          *slog.Logger
}

type Sink struct {
	cfg Config
	tls *tls.Config
}

func New(cfg Config) (*Sink, error) {
	if cfg.Framing == "" {
		cfg.Framing = FramingNewline
	}
	if cfg.Framing != FramingNewline && cfg.Framing != FramingOctetCounting {
		return nil, fmt.Errorf("syslog framing %q must be %s or %s", cfg.Framing, FramingNewline, FramingOctetCounting)
	}
	if cfg.MaxMessageBytes <= 0 {
		cfg.MaxMessageBytes = 32 << 10
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Sink{cfg: cfg}
	if cfg.TLS {
		s.tls = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.Host}
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("reading the syslog CA bundle: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("the syslog CA bundle %s holds no PEM certificates", cfg.CAFile)
			}
			s.tls.RootCAs = pool
		}
	}
	return s, nil
}

func (s *Sink) Kind() string { return "syslog" }

// Deliver sends the batch on one connection, then closes its side and waits for the listener to close too, which
// shows the listener read everything. A listener that never closes is logged and the batch counts as sent.
func (s *Sink) Deliver(ctx context.Context, b *record.Batch) (record.Delivered, error) {
	l := &lease{ctx: ctx, hold: b.Hold}
	if _, err := l.deadline(s.cfg.Timeout); err != nil {
		return record.Delivered{}, err
	}
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	d := &net.Dialer{Timeout: s.cfg.Timeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return record.Delivered{}, fmt.Errorf("connecting to syslog %s: %w", addr, err)
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	defer raw.Close()
	conn := raw
	if s.tls != nil {
		tc := tls.Client(raw, s.tls)
		dl, err := l.deadline(s.cfg.Timeout)
		if err != nil {
			return record.Delivered{}, err
		}
		_ = raw.SetDeadline(dl)
		if err := tc.HandshakeContext(ctx); err != nil {
			return record.Delivered{}, fmt.Errorf("TLS handshake with syslog %s: %w", addr, err)
		}
		conn = tc
	}

	w := bufio.NewWriterSize(&deadlineWriter{conn: conn, timeout: s.cfg.Timeout, lease: l}, 64<<10)
	var sent int64
	for _, r := range b.Records {
		msg := s.Format(b.Source, r)
		n, err := w.Write(msg)
		sent += int64(n)
		if err != nil {
			return record.Delivered{}, s.sendErr(ctx, addr, err)
		}
	}
	if err := w.Flush(); err != nil {
		return record.Delivered{}, s.sendErr(ctx, addr, err)
	}
	if err := s.confirm(conn, raw, l); err != nil {
		return record.Delivered{}, s.sendErr(ctx, addr, err)
	}
	return record.Delivered{Writes: 1, Bytes: sent}, nil
}

func (s *Sink) sendErr(ctx context.Context, addr string, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("sending to syslog %s: %w", addr, ctx.Err())
	}
	return fmt.Errorf("sending to syslog %s: %w", addr, err)
}

func (s *Sink) confirm(conn, raw net.Conn, l *lease) error {
	if tc, ok := conn.(*tls.Conn); ok {
		// close_notify follows the data, so the listener answering it shows it read the whole batch.
		if err := tc.CloseWrite(); err != nil {
			return err
		}
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			return err
		}
	}
	dl, err := l.deadline(s.cfg.Timeout)
	if err != nil {
		return err
	}
	_ = conn.SetReadDeadline(dl)
	_, err = io.Copy(io.Discard, conn)
	var ne net.Error
	switch {
	case err == nil, errors.Is(err, io.ErrUnexpectedEOF):
		return nil
	case errors.As(err, &ne) && ne.Timeout():
		s.cfg.Logger.Warn("syslog listener did not close the connection; treating the batch as sent", "timeout", s.cfg.Timeout.String())
		return nil
	default:
		return err
	}
}

// renewEvery is how often a long send renews the checkpoint lease.
var renewEvery = 15 * time.Second

// errLeaseEnding stops a send that could otherwise go on after another replica took over the stream.
var errLeaseEnding = errors.New("the checkpoint lease is about to expire")

// lease renews the checkpoint lease while a long batch is being sent, and bounds every network deadline by it.
type lease struct {
	ctx     context.Context
	hold    func(context.Context) (context.Context, context.CancelFunc, error)
	until   time.Time
	checked time.Time
}

func (l *lease) deadline(timeout time.Duration) (time.Time, error) {
	now := time.Now()
	if l.checked.IsZero() || now.Sub(l.checked) >= renewEvery {
		c, cancel, err := l.hold(l.ctx)
		if err != nil {
			return time.Time{}, err
		}
		l.until, _ = c.Deadline()
		cancel()
		l.checked = now
	}
	d := now.Add(timeout)
	if !l.until.IsZero() && l.until.Before(d) {
		d = l.until
	}
	if !d.After(now) {
		return d, errLeaseEnding
	}
	return d, nil
}

type deadlineWriter struct {
	conn    net.Conn
	timeout time.Duration
	lease   *lease
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	dl, err := d.lease.deadline(d.timeout)
	if err != nil {
		return 0, err
	}
	_ = d.conn.SetWriteDeadline(dl)
	return d.conn.Write(p)
}

// Format renders one framed RFC 5424 message.
func (s *Sink) Format(src record.Source, r record.Record) []byte {
	host := src.Org
	if src.Kind == record.KindK8sAudit {
		host = src.Name
		if c := r.Attrs["cluster_name"]; c != "" {
			host = c
		}
	}
	app := AppName[src.Kind]
	if app == "" {
		app = src.Kind
	}
	var b strings.Builder
	b.Grow(len(r.Raw) + 512)
	fmt.Fprintf(&b, "<%d>1 %s %s %s - - ", s.cfg.Facility*8+s.cfg.Severity,
		r.Time.UTC().Format("2006-01-02T15:04:05.000000Z"), headerField(host, 255), headerField(app, 48))
	keys := make([]string, 0, len(r.Attrs))
	for k := range r.Attrs {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		b.WriteString("-")
	} else {
		b.WriteString("[" + sdID)
		for _, k := range keys {
			b.WriteString(" " + sdName(k) + `="` + sdValue(r.Attrs[k]) + `"`)
		}
		b.WriteString("]")
	}
	b.WriteString(" " + bom)
	// A raw newline would split the message with newline framing; escaped with either framing so the content
	// does not depend on it.
	b.WriteString(strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(string(r.Raw)))
	msg := truncate(b.String(), s.cfg.MaxMessageBytes)
	if s.cfg.Framing == FramingOctetCounting {
		return []byte(strconv.Itoa(len(msg)) + " " + msg)
	}
	return []byte(msg + "\n")
}

// headerField keeps 1*PRINTUSASCII: anything else would shift the fields after it.
func headerField(v string, maxLen int) string {
	if v == "" {
		return "-"
	}
	out := []rune(v)
	for i, c := range out {
		if c < 33 || c > 126 {
			out[i] = '_'
		}
	}
	return string(out[:min(len(out), maxLen)])
}

// sdName cuts an SD-NAME at 32 characters and replaces anything outside PRINTUSASCII, and '=', ']' and '"', with '_'.
func sdName(k string) string {
	out := []rune(k)
	out = out[:min(len(out), 32)]
	for i, c := range out {
		if c < 33 || c > 126 || c == '=' || c == ']' || c == '"' {
			out[i] = '_'
		}
	}
	return string(out)
}

func sdValue(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(v)
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		if r != utf8.RuneError || size != 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}
