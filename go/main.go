// Command tailnet is the Go/wasm engine behind the tailnet-do JS library.
//
// Loading the module defines globalThis.__tailnet with:
//
//	init(host)            host-level hooks shared by every node:
//	                        dialTCP(host, port) -> Promise<sock>  (cloudflare:sockets)
//	                        dnsQuery(Uint8Array) -> Promise<Uint8Array>
//	                        log(line)
//	newNode(config) -> node
//
// One Go runtime per isolate can host many nodes. A JS socket ("sock") is any
// object with read() -> Promise<Uint8Array|null>, write(u8) -> Promise,
// close(), and optionally closeWrite().
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/tsd"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

var host js.Value // set by init()

func main() {
	api := js.Global().Get("Object").New()
	api.Set("init", js.FuncOf(func(_ js.Value, a []js.Value) any {
		host = a[0]
		installHostHooks()
		return nil
	}))
	api.Set("newNode", js.FuncOf(func(_ js.Value, a []js.Value) any {
		return newNode(a[0])
	}))
	js.Global().Set("__tailnet", api)
	<-make(chan bool)
}

// ---- JS <-> Go plumbing -------------------------------------------------

// await blocks the calling goroutine until the JS promise settles.
func await(p js.Value) (js.Value, error) {
	type result struct {
		v   js.Value
		err error
	}
	ch := make(chan result, 1)
	var then, catch js.Func
	then = js.FuncOf(func(_ js.Value, a []js.Value) any {
		v := js.Undefined()
		if len(a) > 0 {
			v = a[0]
		}
		ch <- result{v: v}
		then.Release()
		catch.Release()
		return nil
	})
	catch = js.FuncOf(func(_ js.Value, a []js.Value) any {
		msg := "promise rejected"
		if len(a) > 0 {
			msg = a[0].Call("toString").String()
		}
		ch <- result{err: errors.New(msg)}
		then.Release()
		catch.Release()
		return nil
	})
	p.Call("then", then, catch)
	r := <-ch
	return r.v, r.err
}

// promise runs f on a new goroutine and returns a JS Promise for its result.
func promise(f func() (any, error)) js.Value {
	var exec js.Func
	exec = js.FuncOf(func(_ js.Value, a []js.Value) any {
		resolve, reject := a[0], a[1]
		go func() {
			v, err := f()
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
			} else {
				resolve.Invoke(v)
			}
		}()
		exec.Release()
		return nil
	})
	return js.Global().Get("Promise").New(exec)
}

func toJSBytes(b []byte) js.Value {
	u := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(u, b)
	return u
}

func fromJSBytes(v js.Value) []byte {
	b := make([]byte, v.Get("byteLength").Int())
	js.CopyBytesToGo(b, v)
	return b
}

func jsonValue(v any) js.Value {
	b, _ := json.Marshal(v)
	return js.Global().Get("JSON").Call("parse", string(b))
}

// jsConn adapts a JS socket object to net.Conn.
type jsConn struct {
	sock          js.Value
	local, remote net.Addr

	rmu     sync.Mutex
	pending []byte
	eof     bool

	wmu       sync.Mutex
	closeOnce sync.Once
}

func (c *jsConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		if c.eof {
			return 0, io.EOF
		}
		v, err := await(c.sock.Call("read"))
		if err != nil {
			return 0, err
		}
		if v.IsNull() || v.IsUndefined() {
			c.eof = true
			continue
		}
		c.pending = fromJSBytes(v)
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *jsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := await(c.sock.Call("write", toJSBytes(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *jsConn) Close() error {
	c.closeOnce.Do(func() { c.sock.Call("close") })
	return nil
}

func (c *jsConn) CloseWrite() error {
	if c.sock.Get("closeWrite").Type() == js.TypeFunction {
		c.sock.Call("closeWrite")
	}
	return nil
}

func (c *jsConn) LocalAddr() net.Addr              { return c.local }
func (c *jsConn) RemoteAddr() net.Addr             { return c.remote }
func (c *jsConn) SetDeadline(time.Time) error      { return nil }
func (c *jsConn) SetReadDeadline(time.Time) error  { return nil }
func (c *jsConn) SetWriteDeadline(time.Time) error { return nil }

// exportConn exposes a Go net.Conn to JS as a sock object.
func exportConn(c net.Conn) js.Value {
	o := js.Global().Get("Object").New()
	buf := make([]byte, 32<<10)
	var rmu sync.Mutex
	o.Set("read", js.FuncOf(func(js.Value, []js.Value) any {
		return promise(func() (any, error) {
			rmu.Lock()
			defer rmu.Unlock()
			n, err := c.Read(buf)
			if n > 0 {
				return toJSBytes(buf[:n]), nil
			}
			if err == io.EOF || errors.Is(err, net.ErrClosed) {
				return js.Null(), nil
			}
			if err != nil {
				return nil, err
			}
			return toJSBytes(nil), nil
		})
	}))
	o.Set("write", js.FuncOf(func(_ js.Value, a []js.Value) any {
		b := fromJSBytes(a[0])
		return promise(func() (any, error) {
			_, err := c.Write(b)
			return js.Undefined(), err
		})
	}))
	o.Set("closeWrite", js.FuncOf(func(js.Value, []js.Value) any {
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		return nil
	}))
	o.Set("close", js.FuncOf(func(js.Value, []js.Value) any {
		c.Close()
		return nil
	}))
	o.Set("remoteAddress", c.RemoteAddr().String())
	o.Set("localAddress", c.LocalAddr().String())
	return o
}

func logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	if host.Truthy() && host.Get("log").Type() == js.TypeFunction {
		host.Call("log", line)
	} else {
		fmt.Println(line)
	}
}

// ---- host-level hooks (shared by all nodes) ----------------------------

func hostDial(ctx context.Context, network, addr string) (net.Conn, error) {
	h, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	sock, err := await(host.Call("dialTCP", h, port))
	if err != nil {
		return nil, err
	}
	ra, _ := net.ResolveTCPAddr("tcp", addr)
	return &jsConn{sock: sock, remote: ra, local: &net.TCPAddr{}}, nil
}

func hostDoH(ctx context.Context, q []byte) ([]byte, error) {
	v, err := await(host.Call("dnsQuery", toJSBytes(q)))
	if err != nil {
		return nil, err
	}
	return fromJSBytes(v), nil
}

func installHostHooks() {
	log.SetFlags(0)
	log.SetOutput(writerFunc(func(p []byte) (int, error) {
		logf("%s", strings.TrimRight(string(p), "\n"))
		return len(p), nil
	}))
	netns.SetEnabled(false)

	// Exit-node DNS (peerapi DoH) goes to the host resolver.
	ipnlocal.ExitNodeDNSOverride = hostDoH

	// Forwarded UDP: DNS via DoH, everything else is dropped. Workers have
	// no UDP sockets, so QUIC and friends fall back to TCP.
	netstack.ForwardUDPHook = func(client *gonet.UDPConn, _, dst netip.AddrPort) {
		defer client.Close()
		if dst.Port() != 53 {
			return
		}
		buf := make([]byte, 4096)
		for {
			client.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := client.Read(buf)
			if err != nil {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			resp, err := hostDoH(ctx, append([]byte(nil), buf[:n]...))
			cancel()
			if err == nil {
				client.Write(resp)
			}
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// ---- nodes ---------------------------------------------------------------

type node struct {
	lb     *ipnlocal.LocalBackend
	ns     *netstack.Impl
	dialer *tsdial.Dialer

	mu        sync.Mutex
	listeners map[uint16]func(net.Conn, netip.AddrPort) // port -> handler
	httpc     *http.Client
}

func newNode(cfg js.Value) js.Value {
	str := func(k string) string {
		if v := cfg.Get(k); v.Type() == js.TypeString {
			return v.String()
		}
		return ""
	}
	n := &node{listeners: map[uint16]func(net.Conn, netip.AddrPort){}}
	onStatus := cfg.Get("onStatus")
	status := func(kv map[string]any) {
		if onStatus.Type() == js.TypeFunction {
			onStatus.Invoke(jsonValue(kv))
		}
	}

	o := js.Global().Get("Object").New()
	started := promise(func() (any, error) {
		return js.Undefined(), n.start(cfg, str, status)
	})
	o.Set("started", started)

	// dial(addr) -> Promise<sock>: TCP to a tailnet host (IP or MagicDNS name).
	o.Set("dial", js.FuncOf(func(_ js.Value, a []js.Value) any {
		addr := a[0].String()
		return promise(func() (any, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c, err := n.dialer.UserDial(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			return exportConn(c), nil
		})
	}))

	// listen(port, onConn): accept tailnet TCP connections to this node.
	o.Set("listen", js.FuncOf(func(_ js.Value, a []js.Value) any {
		cb := a[1]
		n.setListener(uint16(a[0].Int()), func(c net.Conn, src netip.AddrPort) {
			cb.Invoke(exportConn(c), n.whois(src))
		})
		return nil
	}))

	// serveHTTP(port, handler): HTTP server on a tailnet port. handler gets
	// ({method,url,headers,body}, whois) and returns
	// Promise<{status,headers,body}>. Bodies are buffered.
	o.Set("serveHTTP", js.FuncOf(func(_ js.Value, a []js.Value) any {
		n.serveHTTP(uint16(a[0].Int()), a[1])
		return nil
	}))
	o.Set("unlisten", js.FuncOf(func(_ js.Value, a []js.Value) any {
		n.setListener(uint16(a[0].Int()), nil)
		return nil
	}))

	// whois(addr) -> identity of a tailnet peer, or null.
	o.Set("whois", js.FuncOf(func(_ js.Value, a []js.Value) any {
		ap, err := netip.ParseAddrPort(a[0].String())
		if err != nil {
			return js.Null()
		}
		return n.whois(ap)
	}))

	// fetch({method,url,headers,body}) -> Promise<{status,headers,body}>
	// HTTP over the tailnet. Bodies are buffered.
	o.Set("fetch", js.FuncOf(func(_ js.Value, a []js.Value) any {
		req := a[0]
		method, url := req.Get("method").String(), req.Get("url").String()
		var body []byte
		if b := req.Get("body"); b.Truthy() {
			body = fromJSBytes(b)
		}
		hdrs := [][2]string{}
		if h := req.Get("headers"); h.Truthy() {
			for i := 0; i < h.Length(); i++ {
				hdrs = append(hdrs, [2]string{h.Index(i).Index(0).String(), h.Index(i).Index(1).String()})
			}
		}
		return promise(func() (any, error) { return n.fetch(method, url, hdrs, body) })
	}))

	o.Set("status", js.FuncOf(func(js.Value, []js.Value) any { return n.status() }))
	o.Set("logout", js.FuncOf(func(js.Value, []js.Value) any {
		return promise(func() (any, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return js.Undefined(), n.lb.Logout(ctx, nil)
		})
	}))
	return o
}

func (n *node) start(cfg js.Value, str func(string) string, status func(map[string]any)) error {
	authKey, hostname, controlURL := str("authKey"), str("hostname"), str("controlURL")
	if controlURL == "" {
		controlURL = ipn.DefaultControlURL
	}
	var routes []netip.Prefix
	if cfg.Get("exitNode").Truthy() {
		routes = append(routes, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
	}
	if r := cfg.Get("advertiseRoutes"); r.Truthy() {
		for i := 0; i < r.Length(); i++ {
			p, err := netip.ParsePrefix(r.Index(i).String())
			if err != nil {
				return fmt.Errorf("advertiseRoutes: %w", err)
			}
			routes = append(routes, p)
		}
	}
	var tags []string
	if t := cfg.Get("tags"); t.Truthy() {
		for i := 0; i < t.Length(); i++ {
			tags = append(tags, t.Index(i).String())
		}
	}

	var store ipn.StateStore = new(mem.Store)
	if cfg.Get("getState").Type() == js.TypeFunction {
		store = &jsStateStore{get: cfg.Get("getState"), set: cfg.Get("setState")}
	}

	sys := tsd.NewSystem()
	sys.Set(store)
	dialer := &tsdial.Dialer{Logf: logf}
	dialer.SetBus(sys.Bus.Get())
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Dialer:        dialer,
		SetSubsystem:  sys.Set,
		ControlKnobs:  sys.ControlKnobs(),
		HealthTracker: sys.HealthTracker.Get(),
		Metrics:       sys.UserMetricsRegistry(),
		EventBus:      sys.Bus.Get(),
	})
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}
	sys.Set(eng)

	ns, err := netstack.Create(logf, sys.Tun.Get(), eng, sys.MagicSock.Get(), dialer, sys.DNSManager.Get(), sys.ProxyMapper())
	if err != nil {
		return fmt.Errorf("netstack: %w", err)
	}
	ns.SetMetricsRegistry(sys.UserMetricsRegistry())
	ns.SetForwardDialFunc(hostDial)
	sys.Set(ns)
	ns.ProcessLocalIPs = true
	ns.ProcessSubnets = true
	ns.GetTCPHandlerForFlow = n.tcpHandlerForFlow
	dialer.UseNetstackForIP = func(netip.Addr) bool { return true }
	dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		c, err := ns.DialContextTCP(ctx, dst)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	dialer.NetstackDialUDP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		c, err := ns.DialContextUDP(ctx, dst)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	sys.NetstackRouter.Set(true)
	sys.Tun.Get().Start()

	loginFlags := controlclient.LoginDefault
	if cfg.Get("ephemeral").Truthy() {
		loginFlags = controlclient.LoginEphemeral
	}
	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, loginFlags)
	if err != nil {
		return fmt.Errorf("backend: %w", err)
	}
	if err := ns.Start(lb); err != nil {
		return fmt.Errorf("netstack start: %w", err)
	}
	n.lb, n.ns, n.dialer = lb, ns, dialer
	n.httpc = &http.Client{Transport: &http.Transport{DialContext: dialer.UserDial}}

	lb.SetNotifyCallback(func(nt ipn.Notify) {
		if nt.State != nil {
			status(map[string]any{"state": nt.State.String()})
			if *nt.State == ipn.NeedsLogin && authKey == "" {
				go lb.StartLoginInteractive(context.Background())
			}
		}
		if nt.BrowseToURL != nil {
			status(map[string]any{"loginURL": *nt.BrowseToURL})
		}
		if nt.ErrMessage != nil {
			status(map[string]any{"error": *nt.ErrMessage})
		}
		if nt.SelfChange != nil {
			status(map[string]any{"self": true})
		}
	})

	if err := lb.Start(ipn.Options{
		UpdatePrefs: &ipn.Prefs{
			ControlURL:      controlURL,
			WantRunning:     true,
			Hostname:        hostname,
			AdvertiseRoutes: routes,
			AdvertiseTags:   tags,
		},
		AuthKey: authKey,
	}); err != nil {
		return err
	}
	// Start logs in by itself only when the state store has a node key. A
	// new node with an auth key has to be told to, once, here, as tsnet
	// does. (Without a key, the callback above asks for a login URL.) This
	// is not repeated on a later NeedsLogin, so logout() and an expired
	// node key leave the node logged out.
	if authKey != "" && lb.State() == ipn.NeedsLogin {
		return lb.StartLoginInteractive(context.Background())
	}
	return nil
}

func (n *node) tcpHandlerForFlow(src, dst netip.AddrPort) (func(net.Conn), bool) {
	if !n.ns.IsLocalIP(dst.Addr()) {
		return nil, false
	}
	n.mu.Lock()
	h, ok := n.listeners[dst.Port()]
	n.mu.Unlock()
	if !ok {
		return nil, false
	}
	return func(c net.Conn) { h(c, src) }, true
}

func (n *node) setListener(port uint16, h func(net.Conn, netip.AddrPort)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if h == nil {
		delete(n.listeners, port)
	} else {
		n.listeners[port] = h
	}
}

// chanListener is a net.Listener fed by netstack flow handlers.
type chanListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{} }

type whoisKey struct{}

func (n *node) serveHTTP(port uint16, handler js.Value) {
	ln := &chanListener{ch: make(chan net.Conn), closed: make(chan struct{})}
	n.setListener(port, func(c net.Conn, _ netip.AddrPort) {
		select {
		case ln.ch <- c:
		case <-ln.closed:
			c.Close()
		}
	})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req := js.Global().Get("Object").New()
		req.Set("method", r.Method)
		scheme := "http"
		req.Set("url", scheme+"://"+r.Host+r.URL.RequestURI())
		harr := js.Global().Get("Array").New()
		for k, vs := range r.Header {
			for _, v := range vs {
				harr.Call("push", js.ValueOf([]any{k, v}))
			}
		}
		req.Set("headers", harr)
		if len(body) > 0 {
			req.Set("body", toJSBytes(body))
		}
		who := js.Null()
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
			who = n.whois(ap)
		}
		res, err := await(handler.Invoke(req, who))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if h := res.Get("headers"); h.Truthy() {
			for i := 0; i < h.Length(); i++ {
				w.Header().Add(h.Index(i).Index(0).String(), h.Index(i).Index(1).String())
			}
		}
		w.WriteHeader(res.Get("status").Int())
		if b := res.Get("body"); b.Truthy() {
			w.Write(fromJSBytes(b))
		}
	})}
	go srv.Serve(ln)
}

func (n *node) whois(ap netip.AddrPort) js.Value {
	if n.lb == nil {
		return js.Null()
	}
	nv, up, ok := n.lb.WhoIs("tcp", ap)
	if !ok {
		return js.Null()
	}
	var tags []string
	for _, t := range nv.Tags().All() {
		tags = append(tags, t)
	}
	return jsonValue(map[string]any{
		"addr":        ap.String(),
		"loginName":   up.LoginName,
		"displayName": up.DisplayName,
		"nodeName":    strings.TrimSuffix(nv.Name(), "."),
		"tags":        tags,
	})
}

func (n *node) fetch(method, url string, hdrs [][2]string, body []byte) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for _, h := range hdrs {
		req.Header.Add(h[0], h[1])
	}
	resp, err := n.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	out := js.Global().Get("Object").New()
	out.Set("status", resp.StatusCode)
	harr := js.Global().Get("Array").New()
	for k, vs := range resp.Header {
		for _, v := range vs {
			harr.Call("push", js.ValueOf([]any{k, v}))
		}
	}
	out.Set("headers", harr)
	out.Set("body", toJSBytes(b))
	return out, nil
}

func (n *node) status() js.Value {
	if n.lb == nil {
		return jsonValue(map[string]any{"state": "NoState"})
	}
	st := map[string]any{"state": n.lb.State().String()}
	if nm := n.lb.NetMapWithPeers(); nm != nil {
		var addrs []string
		for _, a := range nm.GetAddresses().All() {
			addrs = append(addrs, a.Addr().String())
		}
		st["name"] = strings.TrimSuffix(nm.SelfName(), ".")
		st["addrs"] = addrs
		st["peers"] = len(nm.Peers)
	}
	return jsonValue(st)
}

type jsStateStore struct{ get, set js.Value }

func (s *jsStateStore) ReadState(id ipn.StateKey) ([]byte, error) {
	v := s.get.Invoke(string(id))
	if v.IsNull() || v.IsUndefined() {
		return nil, ipn.ErrStateNotExist
	}
	return hex.DecodeString(v.String())
}

func (s *jsStateStore) WriteState(id ipn.StateKey, bs []byte) error {
	s.set.Invoke(string(id), hex.EncodeToString(bs))
	return nil
}

func (s *jsStateStore) All() func(yield func(ipn.StateKey, []byte) bool) {
	return func(func(ipn.StateKey, []byte) bool) {}
}
