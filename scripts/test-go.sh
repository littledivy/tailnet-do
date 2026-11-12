#!/bin/sh
# Run the Go engine's unit tests. The engine only builds for js/wasm, so the
# test binary runs under Node through the Go toolchain's wasm runner.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root/go"
GOOS=js GOARCH=wasm go test -tags "$(cat tags.txt)" \
  -exec "$(go env GOROOT)/lib/wasm/go_js_wasm_exec" "$@" .
