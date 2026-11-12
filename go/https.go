package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tsweb"
)

// TLS certificates for serveHTTPS.
//
// Tailscale's ACME code (feature/acme) issues the node's certificate, keeps
// it in the state store and decides when it is due for renewal. certManager
// holds the parsed certificate in memory for TLS handshakes and asks
// Tailscale for it again once an hour. That hourly call is what lets
// Tailscale renew: its own refresh loop only runs for hosts in a serve
// config, which this build omits.
//
// Every call into Tailscale can end in an ACME order, and the CA limits
// those (Let's Encrypt: about 5 identical certificates a week and 5 failed
// validations an hour per name). The waits below keep a broken setup from
// running into either limit.

const (
	certRefreshInterval = time.Hour
	certNotRunningPoll  = time.Second
	certDisabledPoll    = time.Minute // costs nothing: the netmap says whether HTTPS is on

	// A call into Tailscale gets certLoadTimeout to finish. If it has not
	// returned certLoadGrace after that, it is given up on, so that one
	// stuck request cannot block handshakes and refreshes for good.
	certLoadTimeout = 3 * time.Minute
	certLoadGrace   = 30 * time.Second

	// After a failed load the next one waits certRetryMin, doubling per
	// consecutive failure up to certRetryMax: at most 4 attempts in the
	// first hour and one an hour after that. Handshakes and renew do not
	// start a load inside that wait.
	certRetryMin = 5 * time.Minute
	certRetryMax = time.Hour

	// certRenewNow is a validity no certificate has, so Tailscale renews.
	certRenewNow = time.Duration(1<<63 - 1)
)

var (
	errNotRunning    = errors.New("node is not connected to the tailnet")
	errHTTPSDisabled = errors.New("HTTPS certificates are not enabled for this tailnet; turn them on in the Tailscale admin console under DNS > HTTPS Certificates")
	errHTTPSClosed   = errors.New("HTTPS listener closed")
)

// acmeDirectory is the ACME directory certificates come from. Tailscale
// reads it from the process environment, so the first serveHTTPS in the
// process picks it for all nodes.
var acmeDirectory struct {
	mu     sync.Mutex
	chosen bool
	url    string // "" is Tailscale's default, Let's Encrypt
}

// useACMEDirectory selects the ACME directory, or checks url against the
// one already selected.
func useACMEDirectory(url string) error {
	name := func(u string) string {
		if u == "" {
			return "the default (Let's Encrypt)"
		}
		return u
	}
	acmeDirectory.mu.Lock()
	defer acmeDirectory.mu.Unlock()
	if !acmeDirectory.chosen {
		acmeDirectory.chosen, acmeDirectory.url = true, url
		if url != "" {
			envknob.Setenv("TS_DEBUG_ACME_DIRECTORY_URL", url)
		}
		return nil
	}
	if url != acmeDirectory.url {
		return fmt.Errorf("acmeDirectoryURL must be the same for every node that serves HTTPS in an isolate: "+
			"another node already uses %s, this one asks for %s", name(acmeDirectory.url), name(url))
	}
	return nil
}

type certManager struct {
	logf func(format string, args ...any)
	now  func() time.Time

	// domain returns the name to get a certificate for. It fails with
	// errNotRunning until the node has a netmap, and with
	// errHTTPSDisabled if the tailnet has no certificate domains.
	domain func() (string, error)

	// getCertPEM is LocalBackend.GetCertPEMWithValidity.
	getCertPEM func(ctx context.Context, domain string, minValidity time.Duration) (*ipnlocal.TLSCertKeyPair, error)

	mu         sync.Mutex
	cert       *tls.Certificate // nil until the first successful load
	certDomain string
	err        error         // what is wrong, if anything; see finishLoad
	failures   int           // consecutive failed loads
	retryAt    time.Time     // after a failure: no new load before this time
	holdUntil  time.Time     // after an unexpected issuance: no refresh before this time
	loading    *certLoad     // non-nil while a load is in flight
	outcome    chan struct{} // closed, and replaced, when a load has an outcome
	users      int           // HTTPS listeners using this manager
	stop       context.CancelFunc
	stopped    chan struct{} // closed when the run started by acquire has returned
	poke       chan struct{} // wakes run when the node's state changes
}

// certLoad is one call into Tailscale, shared by everyone who wants its
// result while it runs.
type certLoad struct {
	renew bool // asked for a new certificate, not the current one
	done  chan struct{}
	cert  *tls.Certificate
	err   error
}

func newCertManager(
	logf func(format string, args ...any),
	domain func() (string, error),
	getCertPEM func(context.Context, string, time.Duration) (*ipnlocal.TLSCertKeyPair, error),
) *certManager {
	return &certManager{
		logf:       logf,
		now:        time.Now,
		domain:     domain,
		getCertPEM: getCertPEM,
		outcome:    make(chan struct{}),
		poke:       make(chan struct{}, 1),
	}
}

// acquire registers an HTTPS listener and starts the refresh loop for the
// first one. Every acquire needs a release.
func (m *certManager) acquire() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users++
	if m.users == 1 {
		ctx, cancel := context.WithCancel(context.Background())
		stopped := make(chan struct{})
		m.stop, m.stopped = cancel, stopped
		go func() {
			defer close(stopped)
			m.run(ctx)
		}()
	}
}

func (m *certManager) release() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users--
	if m.users == 0 {
		m.stop()
		m.stop = nil
	}
}

// stateChanged tells the refresh loop that the node's state changed, so it
// does not have to wait for its next poll to see that the node is running.
func (m *certManager) stateChanged() {
	select {
	case m.poke <- struct{}{}:
	default:
	}
}

// run loads the certificate as soon as the node is running, then keeps it
// fresh until ctx is done.
func (m *certManager) run(ctx context.Context) {
	for {
		wait, running := m.refresh(ctx)
		var poke <-chan struct{}
		if !running {
			poke = m.poke
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-poke:
			t.Stop()
		case <-t.C:
		}
	}
}

// refresh is one iteration of run. It returns how long to wait before the
// next one, and whether the node was running.
func (m *certManager) refresh(ctx context.Context) (wait time.Duration, running bool) {
	m.mu.Lock()
	wait = m.waitLocked()
	m.mu.Unlock()
	if wait > 0 {
		return wait, true
	}
	_, err := m.load(ctx, 0)
	switch {
	case errors.Is(err, errNotRunning):
		return certNotRunningPoll, false
	case errors.Is(err, errHTTPSDisabled):
		return certDisabledPoll, true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if wait := m.waitLocked(); wait > 0 {
		return wait, true
	}
	if err != nil {
		return certRetryMin, true // ctx is done
	}
	return certRefreshInterval, true
}

// waitLocked returns how long refresh has to stay away from Tailscale.
func (m *certManager) waitLocked() time.Duration {
	now := m.now()
	return max(m.retryAt.Sub(now), m.holdUntil.Sub(now))
}

// getCertificate is the tls.Config.GetCertificate of HTTPS listeners. Any
// server name gets the node's certificate: a client that used another name
// then reports the mismatch itself, which says more than a failed handshake.
func (m *certManager) getCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.certificate(hi.Context())
}

// certificate returns the certificate for a handshake that ctx belongs to:
// the one in memory while it is valid, otherwise whatever a load gives.
func (m *certManager) certificate(ctx context.Context) (*tls.Certificate, error) {
	m.mu.Lock()
	cert := m.cert
	waitErr := m.retryErrLocked()
	m.mu.Unlock()
	if cert != nil && m.now().Before(cert.Leaf.NotAfter) {
		return cert, nil
	}
	if waitErr != nil {
		return nil, waitErr
	}
	return m.load(ctx, 0)
}

// retryErrLocked returns an error if the last load failed and the wait
// before the next one is not over.
func (m *certManager) retryErrLocked() error {
	if m.err == nil || !m.now().Before(m.retryAt) {
		return nil
	}
	return fmt.Errorf("no new attempt before %s: %w", m.retryAt.UTC().Format(time.RFC3339), m.err)
}

// load asks Tailscale for the certificate, which comes from the state store
// or is issued, and makes it the current one. Calls that overlap share one
// request. ctx only bounds the wait: the request itself keeps going, so a
// client that gives up on its handshake does not abort an issuance.
func (m *certManager) load(ctx context.Context, minValidity time.Duration) (*tls.Certificate, error) {
	m.mu.Lock()
	l := m.loading
	if l == nil {
		l = m.startLoadLocked(minValidity)
	}
	m.mu.Unlock()
	select {
	case <-l.done:
		return l.cert, l.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// renew replaces the certificate with a newly issued one. Calls that
// overlap share one issuance, and like any other load it waits out the
// delay after a failure.
func (m *certManager) renew(ctx context.Context) (*tls.Certificate, error) {
	for {
		m.mu.Lock()
		l := m.loading
		if l == nil {
			if err := m.retryErrLocked(); err != nil {
				m.mu.Unlock()
				return nil, err
			}
			l = m.startLoadLocked(certRenewNow)
		}
		m.mu.Unlock()
		select {
		case <-l.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if l.renew {
			return l.cert, l.err
		}
		// That was an ordinary load, which hands back the current
		// certificate. Now that it is out of the way, renew.
	}
}

type loadResult struct {
	cert   *tls.Certificate
	domain string
	cached bool
	err    error
}

func (m *certManager) startLoadLocked(minValidity time.Duration) *certLoad {
	l := &certLoad{renew: minValidity == certRenewNow, done: make(chan struct{})}
	m.loading = l
	go func() {
		ch := make(chan loadResult, 1)
		go func() { ch <- m.fetch(minValidity) }()
		var r loadResult
		t := time.NewTimer(certLoadTimeout + certLoadGrace)
		select {
		case r = <-ch:
			t.Stop()
		case <-t.C:
			r.err = fmt.Errorf("getting a certificate: no answer from Tailscale after %v", certLoadTimeout+certLoadGrace)
		}
		m.finishLoad(l, r)
		l.cert, l.err = r.cert, r.err
		close(l.done)
	}()
	return l
}

func (m *certManager) fetch(minValidity time.Duration) loadResult {
	domain, err := m.domain()
	if err != nil {
		return loadResult{err: err}
	}
	ctx, cancel := context.WithTimeout(context.Background(), certLoadTimeout)
	defer cancel()
	pair, err := m.getCertPEM(ctx, domain, minValidity)
	if err != nil {
		return loadResult{domain: domain, err: fmt.Errorf("getting a certificate for %s: %w", domain, err)}
	}
	c, err := tls.X509KeyPair(pair.CertPEM, pair.KeyPEM)
	if err == nil && c.Leaf == nil {
		c.Leaf, err = x509.ParseCertificate(c.Certificate[0])
	}
	if err != nil {
		return loadResult{domain: domain, err: fmt.Errorf("certificate for %s: %w", domain, err)}
	}
	return loadResult{cert: &c, domain: domain, cached: pair.Cached}
}

// finishLoad records the outcome of a load and logs what changed.
//
// m.err is set when a load fails, and cleared when one succeeds. It is also
// set, with a certificate in place, when Tailscale issued a certificate that
// nothing asked for: see below.
func (m *certManager) finishLoad(l *certLoad, r loadResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loading = nil
	if errors.Is(r.err, errNotRunning) {
		return // not an outcome yet; run tries again shortly
	}
	defer func() {
		close(m.outcome)
		m.outcome = make(chan struct{})
	}()
	now := m.now()
	if r.err != nil {
		if m.err == nil || m.err.Error() != r.err.Error() {
			m.logf("https: %v", r.err)
		}
		m.err = r.err
		if !errors.Is(r.err, errHTTPSDisabled) {
			m.failures++
			wait := min(certRetryMin<<min(m.failures-1, 10), certRetryMax)
			m.retryAt = now.Add(max(wait, retryAfter(r.err)))
		}
		return
	}

	prev, prevDomain := m.cert, m.certDomain
	m.cert, m.certDomain, m.err, m.failures, m.retryAt = r.cert, r.domain, nil, 0, time.Time{}
	if r.cached {
		m.holdUntil = time.Time{} // the state store works
	}
	if prev != nil && bytes.Equal(prev.Certificate[0], r.cert.Certificate[0]) {
		return
	}
	expires := r.cert.Leaf.NotAfter.UTC().Format(time.RFC3339)
	switch {
	case !r.cached && !l.renew && prev != nil && prevDomain == r.domain && now.Before(prev.Leaf.NotAfter):
		// Tailscale had to issue, although the certificate it gave us
		// before is still good: it could not read that one back from
		// the state store, or no longer accepts it. Asking again in an
		// hour would issue again, and five of those use up the CA's
		// weekly allowance. This certificate works from memory, so
		// leave Tailscale alone until it is due for renewal.
		leaf := r.cert.Leaf
		m.holdUntil = leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3)
		m.err = fmt.Errorf("the stored certificate for %s was not reused and a new one was issued; "+
			"not asking for it again before %s", r.domain, m.holdUntil.UTC().Format(time.RFC3339))
		m.logf("https: %v", m.err)
	case !r.cached:
		m.logf("https: issued a new certificate for %s, expires %s", r.domain, expires)
	case prev == nil:
		m.logf("https: using the stored certificate for %s, expires %s", r.domain, expires)
	default:
		m.logf("https: using the renewed certificate for %s, expires %s", r.domain, expires)
	}
}

// retryAfter returns how long the CA asked us to wait, if err is Tailscale's
// rate-limit error, which carries that as an HTTP 429 response.
func retryAfter(err error) time.Duration {
	var hs interface{ HTTPStatus() tsweb.HTTPError }
	if !errors.As(err, &hs) {
		return 0
	}
	secs, _ := strconv.Atoi(hs.HTTPStatus().Header.Get("Retry-After"))
	return time.Duration(secs) * time.Second
}

// watch returns a func that reports whether a certificate is in place: at
// once if there is one now, or if the last load failed and the next has to
// wait; otherwise with the outcome of the next load. It is split in two so
// that a caller can start watching before it triggers that load.
func (m *certManager) watch() func(ctx context.Context) (*certInfo, error) {
	m.mu.Lock()
	outcome := m.outcome
	settled := m.cert != nil || m.retryErrLocked() != nil
	m.mu.Unlock()
	return func(ctx context.Context) (*certInfo, error) {
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		if !settled {
			select {
			case <-outcome:
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			}
		}
		info, err := m.info()
		switch {
		case info != nil:
			return info, nil // serving; anything else is in status()
		case err == nil:
			err = errors.New("no TLS certificate")
		}
		return nil, err
	}
}

// certInfo describes the certificate in use.
type certInfo struct {
	Domain string
	Expiry time.Time
}

func (c *certInfo) js() map[string]any {
	return map[string]any{"domain": c.Domain, "expiry": c.Expiry.UTC().Format(time.RFC3339)}
}

// info returns the certificate in use, if any, and what is wrong, if
// anything.
func (m *certManager) info() (*certInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cert == nil {
		return nil, m.err
	}
	return &certInfo{Domain: m.certDomain, Expiry: m.cert.Leaf.NotAfter}, m.err
}
