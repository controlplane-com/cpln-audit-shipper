package syslogsink

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/controlplane-com/cpln-audit-shipper/internal/record"
)

var k8s = record.Source{Kind: record.KindK8sAudit, Org: "acme", Name: "prod-cluster"}

func sink(t *testing.T, cfg Config) *Sink {
	t.Helper()
	if cfg.Facility == 0 && cfg.Severity == 0 {
		cfg.Facility, cfg.Severity = 1, 7
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rec(ts int64, attrs map[string]string, line string) record.Record {
	return record.Record{ID: line, Time: time.Unix(0, ts).UTC(), Raw: []byte(line), Attrs: attrs}
}

func TestFormatMatchesFluentBitRFC5424Layout(t *testing.T) {
	out := sink(t, Config{}).Format(k8s, rec(1763401378_342918123, map[string]string{"job": "audit", "cluster_name": "prod-cluster"}, `{"a":1}`))
	want := "<15>1 2025-11-17T17:42:58.342918Z prod-cluster mk8s-audit - - [cpln@0 cluster_name=\"prod-cluster\" job=\"audit\"] \ufeff{\"a\":1}\n"
	if string(out) != want {
		t.Fatalf("got  %q\nwant %q", out, want)
	}
}

func TestFormatEscapesSDValuesAndSanitisesNames(t *testing.T) {
	out := string(sink(t, Config{}).Format(k8s, rec(0, map[string]string{`we"ird ]key=` + strings.Repeat("x", 40): `a"b\c]d`}, "m")))
	sd := strings.SplitN(strings.SplitN(out, " - - ", 2)[1], " \ufeff", 2)[0]
	if want := `[cpln@0 we_ird__key_` + strings.Repeat("x", 20) + `="a\"b\\c\]d"]`; sd != want {
		t.Fatalf("sd = %s, want %s", sd, want)
	}
}

func TestNewlinesInTheMessageCannotBreakFraming(t *testing.T) {
	out := sink(t, Config{}).Format(k8s, rec(0, nil, "a\nb\r\nc"))
	if bytes.Count(out, []byte("\n")) != 1 || !bytes.HasSuffix(out, []byte(`a\nb\r\nc`+"\n")) {
		t.Fatalf("message = %q", out)
	}
	if !bytes.Contains(out, []byte(" - - - \xef\xbb\xbf")) {
		t.Fatalf("no labels must give the NILVALUE SD: %q", out)
	}
}

func TestFormatTruncatesWithoutSplittingUTF8(t *testing.T) {
	out := sink(t, Config{MaxMessageBytes: 100}).Format(k8s, rec(0, nil, strings.Repeat("é", 200)))
	if len(out) > 101 || !utf8.Valid(out) || !bytes.HasSuffix(out, []byte("\n")) {
		t.Fatalf("len %d valid %v: %q", len(out), utf8.Valid(out), out)
	}
}

func TestOctetCountingFraming(t *testing.T) {
	out := sink(t, Config{Framing: FramingOctetCounting}).Format(k8s, rec(0, nil, "line\nwith newline"))
	n, msg, _ := strings.Cut(string(out), " ")
	if l, _ := strconv.Atoi(n); l != len(msg) || strings.HasSuffix(msg, "\n") {
		t.Fatalf("frame %q", out)
	}
	if _, err := New(Config{Framing: "lf"}); err == nil {
		t.Fatal("an unknown framing was accepted")
	}
}

func TestCplnAuditMessagesUseTheOrgAndTheirOwnAppName(t *testing.T) {
	src := record.Source{Kind: record.KindCplnAudit, Org: "acme", Name: "cpln"}
	out := string(sink(t, Config{}).Format(src, rec(0, map[string]string{"id": "e1", "action": "edit"}, `{"id":"e1"}`)))
	if !strings.HasPrefix(out, `<15>1 1970-01-01T00:00:00.000000Z acme cpln-audit - - [cpln@0 action="edit" id="e1"] `) {
		t.Fatalf("message = %q", out)
	}
}

func batch(recs ...record.Record) *record.Batch {
	return &record.Batch{Source: k8s, Records: recs, Hold: func(ctx context.Context) (context.Context, context.CancelFunc, error) {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		return c, cancel, nil
	}}
}

// serve accepts one connection in the background, reads it to the end and closes it as told.
func serve(t *testing.T, ln net.Listener, onConn func(net.Conn) net.Conn, clean bool) chan []byte {
	t.Helper()
	got := make(chan []byte, 1)
	go func() {
		defer close(got)
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		conn := onConn(raw)
		if tc, ok := conn.(*tls.Conn); ok {
			if err := tc.Handshake(); err != nil {
				return
			}
		}
		body, _ := io.ReadAll(conn)
		got <- body
		if tc, ok := conn.(*tls.Conn); ok && clean {
			_ = tc.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return got
}

func port(ln net.Listener) int { return ln.Addr().(*net.TCPAddr).Port }

func TestDeliversABatchOverTCPAndWaitsForTheListenerToClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got := serve(t, ln, func(c net.Conn) net.Conn { return c }, true)
	s := sink(t, Config{Host: "127.0.0.1", Port: port(ln), Timeout: 5 * time.Second})
	recs := []record.Record{rec(1, nil, "m1"), rec(2, nil, "m2"), rec(3, nil, "m3")}
	out, err := s.Deliver(context.Background(), batch(recs...))
	if err != nil {
		t.Fatal(err)
	}
	var want []byte
	for _, r := range recs {
		want = append(want, s.Format(k8s, r)...)
	}
	if body := <-got; !bytes.Equal(body, want) || out.Bytes != int64(len(want)) {
		t.Fatalf("listener read %q, want %q (sent %d bytes)", body, want, out.Bytes)
	}
}

func TestRefusedConnectionFailsTheBatch(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	p := port(ln)
	ln.Close()
	if _, err := sink(t, Config{Host: "127.0.0.1", Port: p, Timeout: 2 * time.Second}).Deliver(context.Background(), batch(rec(1, nil, "x"))); err == nil {
		t.Fatal("delivery to a closed port succeeded")
	}
}

func TestListenerThatNeverClosesCountsAsSentAfterTheTimeout(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err == nil {
			time.Sleep(3 * time.Second)
			c.Close()
		}
	}()
	start := time.Now()
	if _, err := sink(t, Config{Host: "127.0.0.1", Port: port(ln), Timeout: 300 * time.Millisecond}).Deliver(context.Background(), batch(rec(1, nil, "x"))); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("waited past the timeout for the listener to close")
	}
}

// selfSigned writes a CA-less self-signed certificate for 127.0.0.1 and returns its PEM path and the server config.
func selfSigned(t *testing.T) (string, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func TestDeliversOverTLSAndConfirmsWithEitherClose(t *testing.T) {
	caFile, server := selfSigned(t)
	for _, clean := range []bool{true, false} {
		t.Run("clean="+strconv.FormatBool(clean), func(t *testing.T) {
			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			got := serve(t, ln, func(c net.Conn) net.Conn { return tls.Server(c, server) }, clean)
			s := sink(t, Config{Host: "127.0.0.1", Port: port(ln), TLS: true, CAFile: caFile, Timeout: 5 * time.Second})
			if _, err := s.Deliver(context.Background(), batch(rec(1, nil, "a"), rec(2, nil, "b"))); err != nil {
				t.Fatal(err)
			}
			if body := <-got; bytes.Count(body, []byte("\n")) != 2 {
				t.Fatalf("listener read %q", body)
			}
		})
	}
}

func TestRejectsACertificateFromAnotherCA(t *testing.T) {
	_, server := selfSigned(t)
	otherCA, _ := selfSigned(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	got := serve(t, ln, func(c net.Conn) net.Conn { return tls.Server(c, server) }, true)
	_, err := sink(t, Config{Host: "127.0.0.1", Port: port(ln), TLS: true, CAFile: otherCA, Timeout: 5 * time.Second}).
		Deliver(context.Background(), batch(rec(1, nil, "x")))
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want an unknown-authority error", err)
	}
	if body := <-got; len(body) != 0 {
		t.Fatalf("listener read %q from an unverified client", body)
	}
}

func TestALongSendRenewsTheLeaseAndStopsWhenItIsLost(t *testing.T) {
	old := renewEvery
	renewEvery = 0
	t.Cleanup(func() { renewEvery = old })
	big := strings.Repeat("y", 4000)
	var recs []record.Record
	for i := 0; i < 400; i++ {
		recs = append(recs, rec(int64(i), nil, big))
	}
	for _, lose := range []bool{false, true} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		got := serve(t, ln, func(c net.Conn) net.Conn { return c }, true)
		holds := 0
		b := batch(recs...)
		b.Hold = func(ctx context.Context) (context.Context, context.CancelFunc, error) {
			holds++
			if lose && holds == 5 {
				return nil, nil, errors.New("lost the checkpoint lease")
			}
			c, cancel := context.WithTimeout(ctx, 10*time.Second)
			return c, cancel, nil
		}
		_, err := sink(t, Config{Host: "127.0.0.1", Port: port(ln), Timeout: 5 * time.Second}).Deliver(context.Background(), b)
		body := <-got
		switch {
		case !lose && (err != nil || holds < 10 || bytes.Count(body, []byte("\n")) != len(recs)):
			t.Fatalf("send: err %v after %d lease renewals, %d messages", err, holds, bytes.Count(body, []byte("\n")))
		case lose && err == nil:
			t.Fatal("the send went on after the lease was lost")
		}
	}
}
