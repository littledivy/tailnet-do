#!/bin/sh
# End-to-end test of serveHTTPS that needs no tailnet and no Let's Encrypt.
#
# It runs examples/https-node under `wrangler dev` against fake services
# from Tailscale's test packages (control server, DERP relay, ACME CA; see
# fake/main.go), and calls it from a second tailnet device (client/main.go)
# that verifies the certificate against the fake CA. Checked: first
# issuance, HTTP and HTTPS answers, reuse of the stored certificate after a
# restart, renewal, and the error when the tailnet has HTTPS disabled.
#
# Needs Go, Node with npm, curl, a built src/tailnet.wasm, and loopback ports
# 8610-8612 and 8799. Logs are left in .run/.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
run="$here/.run"
status_url=http://localhost:8799/
token=local-test-token # ACCESS_TOKEN in worker/wrangler.jsonc
wrangler="$root/examples/https-node/node_modules/.bin/wrangler"

rm -rf "$run"
mkdir -p "$run"
[ -x "$wrangler" ] || (cd "$root/examples/https-node" && npm install >/dev/null)
(cd "$here" && go build -o "$run/fake" ./fake && go build -o "$run/client" ./client)

fake_pid=
node_pid=
stop() {
  [ -z "$1" ] && return 0
  kill "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}
trap 'stop "$node_pid"; stop "$fake_pid"' EXIT
trap 'exit 1' INT TERM

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

start_fake() { # [fake flags]
  "$run/fake" -root "$run/acme-root.pem" "$@" >>"$run/fake.log" 2>&1 &
  fake_pid=$!
  i=0
  until curl -s -m 2 -o /dev/null http://127.0.0.1:8612/directory; do
    kill -0 "$fake_pid" 2>/dev/null || fail "fake services did not start: $(tail -3 "$run/fake.log")"
    i=$((i + 1))
    [ $i -lt 20 ] || fail "fake services did not come up"
    sleep 1
  done
}

start_node() { # <state dir>
  (cd "$here/worker" && exec "$wrangler" dev --port 8799 --persist-to "$1") >>"$run/node.log" 2>&1 &
  node_pid=$!
}

status() { curl -s -m 5 -H "authorization: Bearer $token" "$status_url" 2>/dev/null || true; }

wait_status() { # <substring of the node's status JSON>
  i=0
  while [ $i -lt 60 ]; do
    if status | grep -q "$1"; then return 0; fi
    sleep 1
    i=$((i + 1))
  done
  fail "node status never had $1: $(status)"
}

call() { # runs the client, leaves its output in $out
  out=$("$run/client" -root "$run/acme-root.pem" -n 2 2>&1) || fail "client: $out"
  echo "$out" | grep GET || true
}

# The client verifies the certificate against the fake CA and prints
# "verified chains 1" with the serial number, or ERROR.
expect_http() { echo "$out" | grep -q 'GET http://.*: 200 "hello ' || fail "no answer over HTTP"; }
expect_https() {
  [ "$(echo "$out" | grep -c 'GET https://.*: 200 "hello .*verified chains 1')" = 2 ] ||
    fail "no verified answer over HTTPS"
}
serial() { echo "$out" | sed -n 's/.*serial \([0-9]*\).*/\1/p' | sort -u; }
orders() { grep -c 'acme: POST /new-order' "$run/fake.log" || true; }

echo "== first start: issue a certificate"
start_fake
start_node "$run/state"
wait_status certExpiry
call
expect_http
expect_https
[ "$(orders)" = 1 ] || fail "expected 1 ACME order, got $(orders)"
first=$(serial)
[ -n "$first" ] || fail "client reported no certificate serial"

echo "== restart: reuse the stored certificate"
stop "$node_pid"
mv "$run/node.log" "$run/node-first.log"
start_node "$run/state"
wait_status certExpiry
grep -q 'https: using the stored certificate' "$run/node.log" || fail "log does not say the stored certificate was used"
call
expect_https
[ "$(orders)" = 1 ] || fail "a certificate was issued again after the restart"
[ "$(serial)" = "$first" ] || fail "certificate changed across the restart"

echo "== renew"
[ "$(curl -s -m 20 -o /dev/null -w '%{http_code}' -X POST "${status_url}renew")" = 401 ] ||
  fail "renew without the token was not refused"
curl -s -m 300 -X POST -H "authorization: Bearer $token" "${status_url}renew" | grep -q expiry || fail "renew failed"
call
expect_https
[ "$(orders)" = 2 ] || fail "expected 2 ACME orders after renewal, got $(orders)"
[ "$(serial)" != "$first" ] || fail "certificate did not change on renewal"

echo "== tailnet with HTTPS disabled"
stop "$node_pid"
stop "$fake_pid"
mv "$run/node.log" "$run/node-restarted.log"
start_fake -no-https
start_node "$run/state-no-https"
wait_status 'certError":"HTTPS certificates are not enabled'
call
expect_http
echo "$out" | grep -q 'GET https://.*: ERROR' || fail "HTTPS answered on a tailnet without certificates"

echo "PASS"
