#!/usr/bin/env bash
# Walking-skeleton demo: the core thesis end to end on one box.
#   alice creates a TS//SI/TK room; bob (no TK) is refused by alice's client AND by
#   the DS, both refusals logged; carol is added; alice sends; carol reads;
#   an above-ceiling message is refused. Then membership over time: a steward removes
#   erin; carol is debriefed from TK and her steward removes her; dave's credential
#   expires, so he is suspended (not removed) until he refreshes; frank stays expired
#   and the steward's cleanup removes him. Each removed client purges and reports it.
#   Then an ack round trip, a forward within a room's ceiling and one above it (refused),
#   full log verification, and a DS that comes back with a rolled-back log: clients raise
#   an integrity alert and stop sending.
# Usage: scripts/demo.sh   (builds first; uses target/demo and port 7777)
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=${PORT:-7777}
DS=http://127.0.0.1:$PORT
D=target/demo
cargo build -q -p ds -p garble-cli
G=target/debug/garble

rm -rf "$D" && mkdir -p "$D"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
expect_denied() { if "$@"; then echo "!! expected a denial"; exit 1; else [ $? -eq 2 ] || exit 1; fi; }

step "issuer + trust bundle"
$G issuer init --out $D/issuer --log-key "$(target/debug/garble-ds keygen --key $D/ds-log.key 2>/dev/null)"

step "delivery service"
start_ds() {
  target/debug/garble-ds --listen 127.0.0.1:$PORT --trust $D/issuer/trust.json --log-dir "$1" --log-key $D/ds-log.key &
  DS_PID=$!
  for _ in $(seq 50); do curl -s $DS/v1/log/checkpoint >/dev/null && break; sleep 0.1; done
}
trap 'kill $DS_PID 2>/dev/null' EXIT
start_ds $D/log

# enroll USER ACCESS [issuer args…]: (re)issue a credential bound to USER's key, enroll it.
enroll() {
  local user=$1 access=$2; shift 2
  [ -d $D/$user ] || $G --home $D/$user init --user $user --ds $DS --trust $D/issuer/trust.json
  $G issuer issue --issuer $D/issuer --user $user --key "$($G --home $D/$user key)" \
     --access "$access" --out $D/$user.cred.json "$@"
  $G --home $D/$user enroll --credential $D/$user.cred.json
}

step "enroll alice (TS//SI/TK), bob (TS//SI only), carol and erin (TS//SI/TK)"
enroll alice 'TS//SI/TK//NF'
enroll bob 'TS//SI//NF'
enroll carol 'TS//SI/TK//NF'
enroll erin 'TS//SI/TK//NF'

step "a forged identity header gets nothing: the DS wants a signed session"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'x-garble-user: alice' $DS/v1/users/alice/welcomes)
[ "$code" = 401 ] || { echo "!! expected 401, got $code"; exit 1; }
echo "401 as expected"

step "mallory enrolls as alice with a copy of alice's credential: refused (bound to alice's key)"
$G --home $D/mallory init --user alice --ds $DS --trust $D/issuer/trust.json
expect_denied $G --home $D/mallory enroll --credential $D/alice.cred.json

step "alice creates room ops, ceiling TS//SI/TK//NF"
$G --home $D/alice create-room ops --ceiling 'TS//SI/TK//NF'

step "alice adds bob: refused by alice's own client (bob lacks TK)"
expect_denied $G --home $D/alice add ops bob

step "alice forces it past her client: refused by the DS"
expect_denied $G --home $D/alice add ops bob --skip-client-check

step "alice adds carol"
$G --home $D/alice add ops carol

step "alice sends TS//TK//NF"
convoy=$($G --home $D/alice send ops --marking 'TS//TK//NF' 'convoy departs 0400' | sed 's/.*#//')

step "alice tries to send above the ceiling (HCS): refused"
expect_denied $G --home $D/alice send ops --marking 'TS//HCS//NF' 'should never leave alice'

step "carol reads"
$G --home $D/carol read | tee $D/carol.out
grep -q '(TS//TK//NF) alice: convoy departs 0400' $D/carol.out
! grep -q 'should never leave alice' $D/carol.out

step "steward alice adds then removes erin; erin's client purges"
$G --home $D/alice add ops erin
$G --home $D/alice remove ops erin
$G --home $D/erin read | tee $D/erin.out
grep -q 'local copy purged' $D/erin.out

step "carol is not a steward: she can't remove anyone"
expect_denied $G --home $D/carol remove ops alice

step "carol is debriefed from TK: the DS asks steward alice to remove her; alice's client does"
enroll carol 'TS//SI//NF'
$G --home $D/erin read >/dev/null 2>&1 || true   # any authenticated request runs the DS sweep
$G --home $D/alice send ops --marking 'TS//TK//NF' 'carol must not see this'
$G --home $D/alice read | tee $D/alice.out
grep -q 'removed carol' $D/alice.out
$G --home $D/carol read | tee $D/carol2.out
grep -q 'local copy purged' $D/carol2.out
! grep -q 'carol must not see this' $D/carol2.out

step "dave and frank get 6-second credentials; alice adds both; both expire"
enroll dave 'TS//SI/TK//NF' --seconds 6
enroll frank 'TS//SI/TK//NF' --seconds 6
$G --home $D/alice add ops dave
$G --home $D/alice add ops frank
$G --home $D/dave read
sleep 7

step "expired dave is suspended, not removed: his send is refused"
expect_denied $G --home $D/dave send ops --marking 'TS//SI//NF' 'anyone there?'

step "dave refreshes his credential and is back"
enroll dave 'TS//SI/TK//NF'
$G --home $D/dave send ops --marking 'TS//SI//NF' 'dave back on net'
$G --home $D/alice read >/dev/null   # a steward reads before committing: MLS keeps no old epochs

step "steward cleanup removes frank, still expired; frank's client purges"
$G --home $D/alice cleanup ops --expired-for 0 | tee $D/cleanup.out
grep -q 'removed from ops: \[frank\]' $D/cleanup.out
$G --home $D/frank read | tee $D/frank.out
grep -q 'local copy purged' $D/frank.out

step "alice tries to raise the ceiling to include HCS: refused, no member is cleared for HCS"
expect_denied $G --home $D/alice set-ceiling ops --ceiling 'TS//SI/TK/HCS//NF'

step "alice lowers the ceiling to TS//SI; dave sees the change; TK traffic is now refused"
$G --home $D/alice set-ceiling ops --ceiling 'TS//SI//NF'
$G --home $D/dave read | tee $D/dave2.out
grep -q 'set the ceiling to TS//SI//NF' $D/dave2.out
expect_denied $G --home $D/dave send ops --marking 'TS//TK//NF' 'TK no longer belongs here'

step "a DM is just a two-person room"
$G --home $D/alice dm dave --ceiling 'S//NF'
$G --home $D/dave read | tee $D/dave3.out
grep -q '\[dm-alice-dave\] joined' $D/dave3.out

step "dave acks an S//NF message: alice sees a signed ROGER; the ack carries the message's marking"
rdv=$($G --home $D/alice send ops --marking 'S//NF' 'rendezvous at checkpoint 3' | sed 's/.*#//')
$G --home $D/dave read >/dev/null
$G --home $D/dave ack ops $rdv
$G --home $D/alice read | tee $D/ack.out
grep -q "(S//NF) ROGER from dave for #$rdv" $D/ack.out

step "alice forwards it into the DM (ceiling S//NF): fine, marking kept"
$G --home $D/alice forward ops $rdv dm-alice-dave
$G --home $D/dave read | tee $D/fwd.out
grep -q '(S//NF) alice: rendezvous at checkpoint 3 \[forwarded from alice in ops\]' $D/fwd.out

step "alice forwards the TS//TK//NF convoy message into the DM: above its ceiling, refused and logged"
expect_denied $G --home $D/alice forward ops $convoy dm-alice-dave

step "audit log"
$G --home $D/alice log | tee $D/log.out
count() { grep -c -- "$1" $D/log.out; }
[ "$(count ' deny ')" -eq 9 ] || { echo "!! expected 9 denials"; exit 1; }
[ "$(count 'client-denial:forward')" -eq 1 ] || { echo "!! expected the refused forward logged"; exit 1; }
[ "$(count 'removal-requested')" -eq 1 ] || { echo "!! expected 1 removal request (carol)"; exit 1; }
[ "$(count ' suspended ')" -eq 2 ] || { echo "!! expected dave and frank suspended"; exit 1; }
[ "$(count ' resumed ')" -eq 1 ] || { echo "!! expected dave resumed"; exit 1; }
[ "$(count 'purge-receipt')" -eq 3 ] || { echo "!! expected 3 purge receipts"; exit 1; }

step "log verify: every entry a user may read is in the tree the DS signed"
$G --home $D/alice log verify | tee $D/verify.out
grep -q 'entries you may read are in the tree' $D/verify.out
# bob has no TK: the TK entries are withheld from him, and he can still check the rest
$G --home $D/bob log verify | tee $D/verify-bob.out
! grep -q ' 0 withheld' $D/verify-bob.out

step "the DS comes back with an empty log (rolled back): bob's client alerts, stops sending, keeps reading"
kill $DS_PID; wait $DS_PID 2>/dev/null || true
start_ds $D/log-rolled-back
enroll bob 'TS//SI//NF'   # the DS forgot its users
$G --home $D/bob read | tee $D/alert.out
grep -q 'LOG INTEGRITY ALERT' $D/alert.out
expect_denied $G --home $D/bob send ops --marking 'TS//SI//NF' 'business as usual'
if $G --home $D/bob log verify; then echo "!! expected an integrity alert"; exit 1; else [ $? -eq 3 ] || exit 1; fi
echo; echo "demo ok"
