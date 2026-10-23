#!/usr/bin/env bash
# Attachments and the records archive, end to end through the real binaries.
#   alice sends bob a file; the DS holds only ciphertext; bob fetches and decrypts it.
#   The custodian pulls sealed copies and holds no key. A records officer gets a logged
#   ReadArchive permit, everyone else a logged refusal; the custodian opens the archive
#   only with that permit plus the offline key, and a permit works once.
# Usage: scripts/archive-demo.sh   (builds first; uses target/archive-demo and port 7778)
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=${PORT:-7778}
DS=http://127.0.0.1:$PORT
D=target/archive-demo
# CARGO_FLAGS: extra cargo args, e.g. `--features crypto/libcrux` (CI runs every demo on both providers).
cargo build -q -p ds -p garble-cli -p custodian ${CARGO_FLAGS:-}
G=target/debug/garble
C=target/debug/garble-custodian

rm -rf "$D" && mkdir -p "$D"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
expect_denied() { if "$@"; then echo "!! expected a denial"; exit 1; else [ $? -eq 2 ] || exit 1; fi; }
expect_failure() { if "$@"; then echo "!! expected a failure"; exit 1; fi; }

step "issuer (olga is the records officer), delivery service"
$G issuer init --out $D/issuer --records-officers olga \
   --log-key "$(target/debug/garble-ds keygen --key $D/ds-log.key 2>/dev/null)"
target/debug/garble-ds --listen 127.0.0.1:$PORT --trust $D/issuer/trust.json \
   --log-dir $D/log --log-key $D/ds-log.key &
DS_PID=$!
trap 'kill $DS_PID 2>/dev/null' EXIT
for _ in $(seq 50); do curl -s $DS/v1/log/checkpoint >/dev/null && break; sleep 0.1; done

enroll() {
  local user=$1 access=$2
  [ -d $D/$user ] || $G --home $D/$user init --user $user --ds $DS --trust $D/issuer/trust.json
  $G issuer issue --issuer $D/issuer --user $user --key "$($G --home $D/$user key)" \
     --access "$access" --out $D/$user.cred.json
  $G --home $D/$user enroll --credential $D/$user.cred.json
}

step "enroll alice, bob, olga (TS//SI) and carol (S)"
enroll alice 'TS//SI//NF'
enroll bob 'TS//SI//NF'
enroll olga 'TS//SI//NF'
enroll carol 'S//NF'

step "the custodian gets its own DS identity; it needs no clearance and holds no archive key"
$C --home $D/records init --ds $DS --trust $D/issuer/trust.json
$G issuer issue --issuer $D/issuer --user records --key "$($C --home $D/records key)" \
   --access 'U' --out $D/records.cred.json
$C --home $D/records enroll --credential $D/records.cred.json

step "alice creates ops and adds bob; alice sends a file"
$G --home $D/alice create-room ops --ceiling 'TS//SI//NF'
$G --home $D/alice add ops bob
echo 'rally point is the old mill' > $D/plan.txt
$G --home $D/alice send-file ops --marking 'TS//SI//NF' $D/plan.txt
$G --home $D/alice send ops --marking 'TS//SI//NF' 'plan attached'

step "bob sees the file, fetches it, and it decrypts; he won't overwrite it"
$G --home $D/bob read | tee $D/bob.out
grep -q '\[file\] plan.txt (28 bytes)' $D/bob.out
mkdir $D/bob-files
seq=$(sed -n 's/^\[ops #\([0-9]*\)\].*\[file\].*/\1/p' $D/bob.out)
$G --home $D/bob fetch ops $seq --out $D/bob-files
cmp $D/plan.txt $D/bob-files/plan.txt
expect_failure $G --home $D/bob fetch ops $seq --out $D/bob-files

step "carol is not in the room: she has no message to fetch"
expect_failure $G --home $D/carol fetch ops $seq --out $D/bob-files

step "the custodian pulls sealed copies and files; its store holds no plaintext"
$C --home $D/records pull | tee $D/pull.out
grep -q 'pulled 2 messages and 1 files' $D/pull.out
! grep -rq 'rally point\|plan attached' $D/records/archive.jsonl $D/records/blobs

step "carol asks to read the archive: refused and logged (she is not a records officer)"
expect_denied $G --home $D/carol archive-permit ops --reason 'curious' --out $D/carol.permit.json

step "olga, the records officer, gets a logged permit"
$G --home $D/olga archive-permit ops --reason 'records request 42' --out $D/permit.json

step "the custodian opens the archive: permit plus the offline key"
$C --home $D/records read ops --permit $D/permit.json \
   --key $D/issuer/archive-private.hex --files $D/exported | tee $D/read.out
grep -q '"body":"plan attached"' $D/read.out
grep -q 'rally point' $D/exported/*-plan.txt

step "the same permit again: refused, a permit works once"
expect_failure $C --home $D/records read ops --permit $D/permit.json --key $D/issuer/archive-private.hex

step "both attempts are in olga's audit log"
$G --home $D/olga log | tee $D/log.out
grep -q 'deny   carol  ops   archive-read' $D/log.out
grep -q 'permit olga   ops   archive-read' $D/log.out
$G --home $D/olga log verify
echo; echo "archive demo ok"
