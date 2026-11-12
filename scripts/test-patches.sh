#!/bin/sh
# Run the tests our Tailscale patches add, natively, in the patched
# submodule. They use a fake ACME server on loopback.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root/vendor/tailscale"
go test ./feature/acme/ -run 'TLSCertStorer' "$@"
