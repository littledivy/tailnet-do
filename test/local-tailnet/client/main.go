// Command client joins the fake tailnet as a second device and requests
// the HTTPS node's page over HTTP and HTTPS, checking the certificate
// against the fake CA's root.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/tsnet"
)

func main() {
	rootPath := flag.String("root", "acme-root.pem", "fake CA root certificate")
	host := flag.String("host", "https-node", "hostname of the node to call")
	n := flag.Int("n", 3, "HTTPS requests to make, each on a new connection")
	flag.Parse()
	envknob.Setenv("TS_DEBUG_USE_DERP_HTTP", "1") // the fake DERP relay has no TLS

	dir, err := os.MkdirTemp("", "localtailnet-client")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	srv := &tsnet.Server{Dir: dir, Hostname: "client", ControlURL: "http://127.0.0.1:8611", Ephemeral: true, Logf: func(string, ...any) {}}
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	st, err := srv.Up(ctx)
	if err != nil {
		log.Fatal(err)
	}
	var addr string
	for _, p := range st.Peer {
		if p.HostName == *host && len(p.TailscaleIPs) > 0 {
			addr = p.TailscaleIPs[0].String()
		}
	}
	if addr == "" {
		log.Fatalf("no peer named %q on the tailnet", *host)
	}
	name := *host + ".example.ts.net"
	fmt.Printf("%s is %s\n", name, addr)

	rootPEM, err := os.ReadFile(*rootPath)
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rootPEM)
	// The fake control server has no MagicDNS resolver, so dial the peer's
	// address; TLS still verifies the certificate for the MagicDNS name.
	dial := func(ctx context.Context, network, hostport string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(hostport)
		return srv.Dial(ctx, network, net.JoinHostPort(addr, port))
	}
	get := func(url string) {
		client := &http.Client{Timeout: 4 * time.Minute, Transport: &http.Transport{
			DialContext:       dial,
			TLSClientConfig:   &tls.Config{RootCAs: roots},
			ForceAttemptHTTP2: true,
		}}
		defer client.CloseIdleConnections()
		start := time.Now()
		resp, err := client.Get(url)
		if err != nil {
			fmt.Printf("GET %s: ERROR %v (%v)\n", url, err, time.Since(start).Round(time.Millisecond))
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		line := fmt.Sprintf("GET %s: %d %q in %v", url, resp.StatusCode, body, time.Since(start).Round(time.Millisecond))
		if resp.TLS != nil {
			leaf := resp.TLS.PeerCertificates[0]
			line += fmt.Sprintf(" [%s, cert %v serial %v, expires %s, verified chains %d]", resp.TLS.NegotiatedProtocol,
				leaf.DNSNames, leaf.SerialNumber, leaf.NotAfter.Format(time.RFC3339), len(resp.TLS.VerifiedChains))
		}
		fmt.Println(line)
	}
	get("http://" + name + "/")
	for range *n {
		get("https://" + name + "/")
	}
}
