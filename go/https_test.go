package main

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
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall/js"
	"testing"
	"time"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tsweb"
)

const testDomain = "node.example.ts.net"

// testCA issues certificates for tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

var testSerial int64 = 1

// issue returns a certificate for testDomain valid from notBefore to
// notAfter, as Tailscale would return it.
func (ca *testCA) issue(t *testing.T, notBefore, notAfter time.Time, cached bool) *ipnlocal.TLSCertKeyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	testSerial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(testSerial),
		Subject:      pkix.Name{CommonName: testDomain},
		DNSNames:     []string{testDomain},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &ipnlocal.TLSCertKeyPair{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		Cached:  cached,
	}
}

// fakeTailscale stands in for the LocalBackend behind a certManager.
type fakeTailscale struct {
	mu          sync.Mutex
	now         time.Time
	domainErr   error
	pair        *ipnlocal.TLSCertKeyPair
	err         error
	calls       int
	validities  []time.Duration
	block       chan struct{} // if non-nil, getCertPEM waits for it
	logs        []string
	certManager *certManager
}

func newFakeTailscale(t *testing.T) *fakeTailscale {
	f := &fakeTailscale{now: time.Now()}
	f.certManager = newCertManager(
		func(format string, args ...any) {
			line := fmt.Sprintf(format, args...)
			t.Log(line)
			f.mu.Lock()
			f.logs = append(f.logs, line)
			f.mu.Unlock()
		},
		func() (string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return testDomain, f.domainErr
		},
		func(ctx context.Context, domain string, minValidity time.Duration) (*ipnlocal.TLSCertKeyPair, error) {
			f.mu.Lock()
			f.calls++
			f.validities = append(f.validities, minValidity)
			block, pair, err := f.block, f.pair, f.err
			f.mu.Unlock()
			if domain != testDomain {
				return nil, fmt.Errorf("asked for %q, want %q", domain, testDomain)
			}
			if block != nil {
				<-block
			}
			return pair, err
		},
	)
	f.certManager.now = func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.now
	}
	return f
}

func (f *fakeTailscale) set(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func (f *fakeTailscale) numCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeTailscale) logged(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.logs {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

// handlerForTest returns what netstack would call for a connection to port.
func (n *node) handlerForTest(port uint16) (func(net.Conn), bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	l, ok := n.listeners[port]
	if !ok {
		return nil, false
	}
	return func(c net.Conn) { l.handle(c, netip.AddrPort{}) }, true
}

// soon bounds a wait that should be over quickly, so that a regression
// fails its test instead of hanging the run.
func soon(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func samePair(c *tls.Certificate, p *ipnlocal.TLSCertKeyPair) bool {
	block, _ := pem.Decode(p.CertPEM)
	return c != nil && bytes.Equal(c.Certificate[0], block.Bytes)
}

func TestCertManagerServesFromMemory(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	m := f.certManager
	stored := ca.issue(t, f.now.Add(-time.Hour), f.now.Add(90*24*time.Hour), true)
	f.set(func() { f.pair = stored })

	for i := range 3 {
		cert, err := m.certificate(soon(t))
		if err != nil {
			t.Fatalf("handshake %d: %v", i, err)
		}
		if !samePair(cert, stored) {
			t.Fatalf("handshake %d: got a different certificate", i)
		}
	}
	if n := f.numCalls(); n != 1 {
		t.Errorf("Tailscale was asked for the certificate %d times, want 1", n)
	}
	if !f.logged("using the stored certificate for " + testDomain) {
		t.Error("no log line says the stored certificate was used")
	}
	info, err := m.info()
	if err != nil || info == nil || info.Domain != testDomain || !info.Expiry.Equal(m.cert.Leaf.NotAfter) {
		t.Errorf("info = %+v, %v", info, err)
	}
}

func TestCertManagerLogsIssuance(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	f.set(func() { f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(90*24*time.Hour), false) })
	if _, err := f.certManager.load(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if !f.logged("issued a new certificate for " + testDomain) {
		t.Error("no log line says a certificate was issued")
	}
}

func TestCertManagerHTTPSDisabled(t *testing.T) {
	f := newFakeTailscale(t)
	m := f.certManager
	f.set(func() { f.domainErr = errHTTPSDisabled })
	ready := m.watch()

	_, err := m.certificate(soon(t))
	if !errors.Is(err, errHTTPSDisabled) {
		t.Fatalf("handshake error = %v, want errHTTPSDisabled", err)
	}
	if _, err := ready(soon(t)); !errors.Is(err, errHTTPSDisabled) {
		t.Errorf("ready = %v, want errHTTPSDisabled", err)
	}
	if n := f.numCalls(); n != 0 {
		t.Errorf("Tailscale was asked for a certificate %d times with HTTPS disabled", n)
	}
	if wait, _ := m.refresh(soon(t)); wait != certDisabledPoll {
		t.Errorf("refresh wait = %v, want %v", wait, certDisabledPoll)
	}

	// Enabled in the admin console. A listener added now must hear about
	// the certificate, not about the old failure.
	ca := newTestCA(t)
	f.set(func() {
		f.domainErr = nil
		f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), false)
	})
	ready = m.watch()
	if _, err := m.certificate(soon(t)); err != nil {
		t.Fatalf("handshake after enabling HTTPS: %v", err)
	}
	if info, err := ready(soon(t)); err != nil || info.Domain != testDomain {
		t.Errorf("ready after enabling HTTPS = %+v, %v", info, err)
	}
	if _, err := m.info(); err != nil {
		t.Errorf("error still reported after a successful load: %v", err)
	}
	// With a certificate in place there is nothing to wait for.
	if info, err := m.watch()(soon(t)); err != nil || info == nil {
		t.Errorf("ready with a certificate in place = %+v, %v", info, err)
	}
}

func TestCertManagerNotRunningIsNotAnOutcome(t *testing.T) {
	f := newFakeTailscale(t)
	m := f.certManager
	f.set(func() { f.domainErr = errNotRunning })
	ready := m.watch()

	wait, running := m.refresh(soon(t))
	if running || wait != certNotRunningPoll {
		t.Errorf("refresh = %v, %v; want %v, false", wait, running, certNotRunningPoll)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := ready(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("ready while the node is not running = %v, want it to keep waiting", err)
	}
	if _, err := m.info(); err != nil {
		t.Errorf("info error = %v, want none", err)
	}
}

func TestCertManagerBacksOffAfterFailure(t *testing.T) {
	f := newFakeTailscale(t)
	m := f.certManager
	f.set(func() { f.err = errors.New("acme: validation failed") })
	start := f.now

	if _, err := m.certificate(soon(t)); err == nil {
		t.Fatal("handshake succeeded without a certificate")
	}
	// Handshakes, refreshes, renewals and new listeners inside the wait
	// must not reach Tailscale (and through it, Let's Encrypt).
	for range 5 {
		_, err := m.certificate(soon(t))
		if err == nil || !strings.Contains(err.Error(), "validation failed") {
			t.Fatalf("handshake in backoff: err = %v, want the load error", err)
		}
		if _, err := m.renew(soon(t)); err == nil || !strings.Contains(err.Error(), "validation failed") {
			t.Fatalf("renew in backoff: err = %v, want the load error", err)
		}
		if _, err := m.watch()(soon(t)); err == nil || !strings.Contains(err.Error(), "validation failed") {
			t.Fatalf("ready in backoff: err = %v, want the load error", err)
		}
	}
	if wait, _ := m.refresh(soon(t)); wait != certRetryMin {
		t.Errorf("refresh wait in backoff = %v, want %v", wait, certRetryMin)
	}
	if n := f.numCalls(); n != 1 {
		t.Fatalf("Tailscale was asked %d times, want 1", n)
	}

	// Each failure doubles the wait, up to certRetryMax. Follow the
	// schedule the refresh loop would, and count attempts per hour.
	want := certRetryMin
	var attempts []time.Duration // since start
	attempts = append(attempts, 0)
	for i := 2; i < 12; i++ {
		f.set(func() { f.now = f.now.Add(want) })
		attempts = append(attempts, f.now.Sub(start))
		want = min(want*2, certRetryMax)
		if wait, _ := m.refresh(soon(t)); wait != want {
			t.Fatalf("wait after failure %d = %v, want %v", i, wait, want)
		}
		if n := f.numCalls(); n != i {
			t.Fatalf("Tailscale was asked %d times after %d backoffs, want %d", n, i-1, i)
		}
	}
	// Let's Encrypt allows 5 failed validations per name per hour.
	for i, from := range attempts {
		n := 0
		for _, at := range attempts[i:] {
			if at-from < time.Hour {
				n++
			}
		}
		if n > 4 {
			t.Errorf("%d attempts in the hour from %v: %v", n, from, attempts)
		}
	}

	// Success clears the backoff: the next failure starts over.
	ca := newTestCA(t)
	f.set(func() {
		f.now = f.now.Add(certRetryMax)
		f.err = nil
		f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), true)
	})
	if wait, _ := m.refresh(soon(t)); wait != certRefreshInterval {
		t.Errorf("wait after success = %v, want %v", wait, certRefreshInterval)
	}
	if _, err := m.certificate(soon(t)); err != nil {
		t.Errorf("handshake after recovery: %v", err)
	}
	f.set(func() { f.err = errors.New("acme: validation failed") })
	if wait, _ := m.refresh(soon(t)); wait != certRetryMin {
		t.Errorf("wait after the first failure following a success = %v, want %v", wait, certRetryMin)
	}
}

// rateLimited is shaped like Tailscale's error for an ACME rate limit.
type rateLimited struct{ retryAfter time.Duration }

func (e rateLimited) Error() string { return "acme: too many certificates" }
func (e rateLimited) HTTPStatus() tsweb.HTTPError {
	h := http.Header{}
	h.Set("Retry-After", strconv.Itoa(int(e.retryAfter.Seconds())))
	return tsweb.HTTPError{Code: http.StatusTooManyRequests, Header: h}
}

func TestCertManagerHonoursRetryAfter(t *testing.T) {
	f := newFakeTailscale(t)
	m := f.certManager
	f.set(func() { f.err = rateLimited{retryAfter: 36 * time.Hour} })
	if wait, _ := m.refresh(soon(t)); wait != 36*time.Hour {
		t.Errorf("wait after a rate limit with Retry-After 36h = %v", wait)
	}
	f.set(func() { f.now = f.now.Add(35 * time.Hour) })
	m.refresh(soon(t))
	m.certificate(soon(t))
	if n := f.numCalls(); n != 1 {
		t.Errorf("Tailscale was asked %d times before Retry-After was over, want 1", n)
	}
}

// TestCertManagerStopsAfterUnexpectedIssuance covers a state store that
// does not give back the certificate it was given, or a stored certificate
// Tailscale no longer accepts: every load would be a new issuance.
func TestCertManagerStopsAfterUnexpectedIssuance(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	m := f.certManager
	issue := func() {
		f.set(func() { f.pair = ca.issue(t, f.now, f.now.Add(90*24*time.Hour), false) })
	}

	issue()
	if wait, _ := m.refresh(soon(t)); wait != certRefreshInterval {
		t.Fatalf("wait after the first issuance = %v, want %v", wait, certRefreshInterval)
	}
	// An hour later Tailscale issues again instead of returning that one.
	f.set(func() { f.now = f.now.Add(certRefreshInterval) })
	issue()
	wait, _ := m.refresh(soon(t))
	if want := 60*24*time.Hour - time.Second; wait < want {
		t.Fatalf("wait after an unexpected issuance = %v, want about 60 days (2/3 of the lifetime)", wait)
	}
	if _, err := m.info(); err == nil || !strings.Contains(err.Error(), "not reused") {
		t.Errorf("status error = %v, want it to say the stored certificate was not reused", err)
	}
	for range 24 * 30 {
		f.set(func() { f.now = f.now.Add(certRefreshInterval) })
		issue()
		m.refresh(soon(t))
		if _, err := m.certificate(soon(t)); err != nil {
			t.Fatalf("handshake while holding off: %v", err)
		}
	}
	if n := f.numCalls(); n != 2 {
		t.Errorf("Tailscale was asked %d times in 30 days, want 2", n)
	}

	// A renewal that was asked for is not held back, and is not mistaken
	// for the same problem.
	issue()
	if _, err := m.renew(soon(t)); err != nil {
		t.Fatalf("renew while holding off: %v", err)
	}
	if n := f.numCalls(); n != 3 {
		t.Errorf("Tailscale was asked %d times after renew, want 3", n)
	}
}

func TestCertManagerPicksUpRenewal(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	m := f.certManager
	old := ca.issue(t, f.now.Add(-60*24*time.Hour), f.now.Add(30*24*time.Hour), true)
	f.set(func() { f.pair = old })
	if wait, _ := m.refresh(soon(t)); wait != certRefreshInterval {
		t.Fatalf("refresh wait = %v, want %v", wait, certRefreshInterval)
	}

	// Tailscale renewed in the background; the hourly refresh sees it.
	renewed := ca.issue(t, f.now, f.now.Add(90*24*time.Hour), true)
	f.set(func() { f.pair = renewed })
	if cert, _ := m.certificate(soon(t)); !samePair(cert, old) {
		t.Fatal("handshake before the refresh did not use the certificate in memory")
	}
	m.refresh(soon(t))
	if cert, _ := m.certificate(soon(t)); !samePair(cert, renewed) {
		t.Fatal("handshake after the refresh did not use the renewed certificate")
	}
	if !f.logged("using the renewed certificate") {
		t.Error("no log line says the renewed certificate was picked up")
	}
}

func TestCertManagerReloadsExpiredCert(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	m := f.certManager
	f.set(func() { f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), true) })
	if _, err := m.certificate(soon(t)); err != nil {
		t.Fatal(err)
	}

	fresh := ca.issue(t, f.now, f.now.Add(48*time.Hour), false)
	f.set(func() {
		f.now = f.now.Add(2 * time.Hour)
		f.pair = fresh
	})
	cert, err := m.certificate(soon(t))
	if err != nil {
		t.Fatal(err)
	}
	if !samePair(cert, fresh) {
		t.Error("handshake used the expired certificate")
	}
}

func TestCertManagerSharesOneLoad(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	m := f.certManager
	block := make(chan struct{})
	f.set(func() {
		f.block = block
		f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), false)
	})

	const handshakes = 8
	errs := make(chan error, handshakes)
	for range handshakes {
		go func() {
			_, err := m.certificate(soon(t))
			errs <- err
		}()
	}
	// A waiter that gives up must not cancel the load for the others.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.load(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Errorf("load with a canceled context = %v", err)
	}
	close(block)
	for range handshakes {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	if n := f.numCalls(); n != 1 {
		t.Errorf("Tailscale was asked %d times for %d concurrent handshakes, want 1", n, handshakes)
	}
}

func TestCertManagerRenew(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	m := f.certManager
	stored := ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), true)
	f.set(func() { f.pair = stored })
	if _, err := m.load(soon(t), 0); err != nil {
		t.Fatal(err)
	}

	// An ordinary load is in flight when two renewals are asked for. They
	// must wait for it, then share one issuance between them.
	block := make(chan struct{})
	f.set(func() { f.block = block })
	loaded := make(chan *tls.Certificate, 1)
	go func() {
		c, _ := m.load(soon(t), 0)
		loaded <- c
	}()
	for f.numCalls() < 2 {
		time.Sleep(time.Millisecond)
	}
	renewed := ca.issue(t, f.now, f.now.Add(48*time.Hour), false)
	type result struct {
		cert *tls.Certificate
		err  error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			c, err := m.renew(soon(t))
			results <- result{c, err}
		}()
	}
	time.Sleep(20 * time.Millisecond) // let both reach the wait
	if n := f.numCalls(); n != 2 {
		t.Fatalf("renew did not wait for the load in flight: %d calls", n)
	}
	close(block)
	if c := <-loaded; !samePair(c, stored) {
		t.Error("the load in flight did not return the stored certificate")
	}
	f.set(func() { f.block, f.pair = nil, renewed })
	for range 2 {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		if !samePair(r.cert, renewed) {
			t.Error("renew returned the certificate of the ordinary load")
		}
	}
	if n := f.numCalls(); n != 3 {
		t.Errorf("Tailscale was asked %d times for a load and two overlapping renewals, want 3", n)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := f.validities[len(f.validities)-1]; got != certRenewNow {
		t.Errorf("renew asked Tailscale for validity %v, want %v", got, certRenewNow)
	}
}

// TestCertManagerRun runs the real refresh loop: it has to wait for the
// node, react to a state change without waiting for its poll, and end with
// the last listener and not before.
func TestCertManagerRun(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	m := f.certManager
	f.set(func() { f.domainErr = errNotRunning })
	ready := m.watch()
	m.acquire()
	m.acquire() // a second listener
	time.Sleep(50 * time.Millisecond)
	if n := f.numCalls(); n != 0 {
		t.Fatalf("Tailscale was asked %d times while the node was not running", n)
	}

	// The node comes up. The loop is told and loads at once, well inside
	// its one-second poll.
	f.set(func() {
		f.domainErr = nil
		f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), true)
	})
	start := time.Now()
	m.stateChanged()
	if _, err := ready(soon(t)); err != nil {
		t.Fatalf("run did not load the certificate: %v", err)
	}
	if d := time.Since(start); d > certNotRunningPoll/2 {
		t.Errorf("certificate loaded %v after the state change, want it at once", d)
	}

	m.release()
	m.mu.Lock()
	stopped := m.stopped
	m.mu.Unlock()
	select {
	case <-stopped:
		t.Fatal("refresh loop ended while a listener was left")
	case <-time.After(20 * time.Millisecond):
	}
	m.release()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh loop still running after the last release")
	}
}

// TestCertManagerRunPolls checks that the loop keeps going by itself: with
// no state change announced, its poll finds that the node came up.
func TestCertManagerRunPolls(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	m := f.certManager
	f.set(func() { f.domainErr = errNotRunning })
	ready := m.watch()
	m.acquire()
	defer m.release()
	time.Sleep(50 * time.Millisecond) // the first pass has seen "not running"
	f.set(func() {
		f.domainErr = nil
		f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), true)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*certNotRunningPoll)
	defer cancel()
	if _, err := ready(ctx); err != nil {
		t.Fatalf("the poll did not pick the certificate up: %v", err)
	}
}

// TestServeHTTPS runs a request through the same listener, TLS config and
// handler adapter that serveHTTPS sets up, with a JS handler on the other
// side, and checks the certificate the client sees.
func TestServeHTTPS(t *testing.T) {
	ca := newTestCA(t)
	f := newFakeTailscale(t)
	f.set(func() { f.pair = ca.issue(t, f.now.Add(-time.Hour), f.now.Add(time.Hour), true) })

	handler := js.FuncOf(func(_ js.Value, a []js.Value) any {
		req := a[0]
		res := js.Global().Get("Object").New()
		res.Set("status", 200)
		res.Set("headers", js.ValueOf([]any{[]any{"content-type", "text/plain"}}))
		res.Set("body", toJSBytes([]byte(req.Get("method").String()+" "+req.Get("url").String())))
		return js.Global().Get("Promise").Call("resolve", res)
	})
	defer handler.Release()

	n := &node{listeners: map[uint16]portListener{}, certs: f.certManager}
	ready := n.serveHTTPS(443, handler.Value)
	defer n.setListener(443, nil, nil)
	if info, err := ready(); err != nil || info.Domain != testDomain {
		t.Fatalf("ready = %+v, %v", info, err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	for _, proto := range []string{"http/1.1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			client := &http.Client{Transport: &http.Transport{
				ForceAttemptHTTP2: proto == "h2",
				TLSClientConfig:   &tls.Config{RootCAs: roots, NextProtos: []string{proto}},
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					c, s := net.Pipe()
					handle, ok := n.handlerForTest(443)
					if !ok {
						return nil, errors.New("nothing listens on 443")
					}
					go handle(s)
					return c, nil
				},
			}}
			defer client.CloseIdleConnections()
			resp, err := client.Get("https://" + testDomain + "/hello?x=1")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if want := "GET https://" + testDomain + "/hello?x=1"; string(body) != want {
				t.Errorf("body = %q, want %q", body, want)
			}
			if resp.TLS == nil || resp.TLS.NegotiatedProtocol != proto {
				t.Errorf("negotiated protocol = %+v, want %s", resp.TLS, proto)
			}
			if got := resp.Header.Get("content-type"); got != "text/plain" {
				t.Errorf("content-type = %q", got)
			}
		})
	}

	// Closing the listener stops the refresh loop it started.
	n.setListener(443, nil, nil)
	if f.certManager.users != 0 {
		t.Errorf("certManager has %d users after the listener closed", f.certManager.users)
	}
}

func TestSetListenerClosesTheOneItReplaces(t *testing.T) {
	n := &node{listeners: map[uint16]portListener{}}
	var closed []string
	handle := func(net.Conn, netip.AddrPort) {}
	n.setListener(443, handle, func() { closed = append(closed, "first") })
	n.setListener(443, handle, func() { closed = append(closed, "second") })
	if len(closed) != 1 || closed[0] != "first" {
		t.Fatalf("after replacing the listener, closed = %v, want [first]", closed)
	}
	n.setListener(443, nil, nil)
	n.setListener(443, nil, nil)
	if len(closed) != 2 || closed[1] != "second" {
		t.Fatalf("after unlisten, closed = %v, want [first second]", closed)
	}
}

func TestServeHTTPSReadyFailsWhenClosed(t *testing.T) {
	f := newFakeTailscale(t)
	f.set(func() { f.domainErr = errNotRunning })
	n := &node{listeners: map[uint16]portListener{}, certs: f.certManager}
	ready := n.serveHTTPS(443, js.Undefined())
	n.setListener(443, nil, nil)
	if _, err := ready(); !errors.Is(err, errHTTPSClosed) {
		t.Errorf("ready after close = %v, want errHTTPSClosed", err)
	}
}
