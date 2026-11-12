// Command fake runs a local stand-in for a tailnet's services, all on
// loopback and all from Tailscale's own test packages: a control server, a
// DERP relay that speaks WebSocket, and an ACME CA whose dns-01 validation
// reads the TXT records nodes publish through the control server.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"sync"

	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/acmetest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
)

func main() {
	rootOut := flag.String("root", "acme-root.pem", "where to write the fake CA's root certificate")
	noCerts := flag.Bool("no-https", false, "offer no cert domains, like a tailnet with HTTPS disabled")
	flag.Parse()
	const derpAddr, controlAddr, acmeAddr = "127.0.0.1:8610", "127.0.0.1:8611", "127.0.0.1:8612"

	d := derpserver.New(key.NewNode(), log.Printf)
	go func() {
		log.Fatal(http.ListenAndServe(derpAddr, derpserver.AddWebSocketSupport(d, derpserver.Handler(d))))
	}()

	var mu sync.Mutex
	txt := map[string][]string{}
	acme := acmetest.New("http://" + acmeAddr)
	acme.LookupTXT = func(name string) []string {
		mu.Lock()
		defer mu.Unlock()
		return txt[name]
	}
	if err := os.WriteFile(*rootOut, acme.RootPEM(), 0644); err != nil {
		log.Fatal(err)
	}
	go func() {
		log.Fatal(http.ListenAndServe(acmeAddr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("acme: %s %s", r.Method, r.URL.Path)
			acme.ServeHTTP(w, r)
		})))
	}()

	control := &testcontrol.Server{
		ExplicitBaseURL:  "http://" + controlAddr,
		AllNodesSameUser: true,
		AllOnline:        true,
		DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {RegionID: 1, RegionCode: "local", Nodes: []*tailcfg.DERPNode{{
				Name: "local1", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none",
				DERPPort: 8610, STUNPort: -1, InsecureForTests: true,
			}}},
		}},
		OnSetDNS: func(req *tailcfg.SetDNSRequest) error {
			log.Printf("control: set-dns %s TXT %q", req.Name, req.Value)
			mu.Lock()
			defer mu.Unlock()
			txt[req.Name] = append(txt[req.Name], req.Value)
			return nil
		},
	}
	if !*noCerts {
		control.DNSConfig = &tailcfg.DNSConfig{}
		control.MagicDNSDomain = "example.ts.net"
	}
	log.Printf("control http://%s, derp http://%s, acme http://%s/directory", controlAddr, derpAddr, acmeAddr)
	log.Fatal(http.ListenAndServe(controlAddr, control))
}
