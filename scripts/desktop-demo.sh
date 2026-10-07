#!/usr/bin/env bash
# Opens alice's desktop console on a seeded DS: rooms ops (TS//SI//NF) and watch (S//NF),
# bob already in both with a few messages. Bob stays a CLI user, so while the window is
# up you can talk to alice from another terminal:
#   target/debug/garble --home target/desktop-demo/bob send ops --marking 'S//NF' 'hi alice'
#   target/debug/garble --home target/desktop-demo/bob read
# Usage: scripts/desktop-demo.sh   (builds the UI and the app first; port 7778)
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=${PORT:-7778}
DS=http://127.0.0.1:$PORT
D=target/desktop-demo

(cd crates/garble-desktop/ui && npm ci --silent && npm run --silent build)
cargo build -q -p ds -p garble-cli -p garble-desktop
G=target/debug/garble

rm -rf "$D" && mkdir -p "$D"
$G issuer init --out $D/issuer --log-key "$(target/debug/garble-ds keygen --key $D/ds-log.key 2>/dev/null)" >/dev/null
target/debug/garble-ds --listen 127.0.0.1:$PORT --trust $D/issuer/trust.json --log-dir $D/log --log-key $D/ds-log.key &
DS_PID=$!
trap 'kill $DS_PID 2>/dev/null' EXIT
for _ in $(seq 50); do curl -s $DS/v1/log/checkpoint >/dev/null && break; sleep 0.1; done

# One KeyPackage per enrollment, so a user joining two rooms enrolls twice.
enroll() {
  [ -d $D/$1 ] || $G --home $D/$1 init --user $1 --ds $DS --trust $D/issuer/trust.json >/dev/null
  $G issuer issue --issuer $D/issuer --user $1 --key "$($G --home $D/$1 key)" --access "$2" --out $D/$1.cred.json >/dev/null
  $G --home $D/$1 enroll --credential $D/$1.cred.json >/dev/null
}
enroll alice 'TS//SI/TK//NF'
enroll bob 'TS//SI//NF'
enroll carol 'S//NF'

$G --home $D/alice create-room ops --ceiling 'TS//SI//NF'
$G --home $D/alice create-room watch --ceiling 'S//NF'
$G --home $D/alice add ops bob
enroll bob 'TS//SI//NF'
$G --home $D/alice add watch bob
$G --home $D/bob read >/dev/null
$G --home $D/bob send ops --marking 'TS//SI//NF' 'package is staged, awaiting go'
$G --home $D/bob send ops --marking 'U' 'lunch is at noon'
$G --home $D/bob send watch --marking 'S//NF' 'quiet night'

echo "alice's console is opening; bob is at: $G --home $D/bob"
target/debug/garble-desktop --home $D/alice
