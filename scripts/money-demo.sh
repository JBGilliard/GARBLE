#!/usr/bin/env bash
# The money demo (docs/idea-v1.md §0, §1a): an under-cleared add is refused at four
# independent points, and when a compromised DS lets one through, the room forks,
# freezes, and the fork is logged.
#
#   you    TS//SI//NF   room steward
#   member TS//SI//NF   already in the room
#   friend SECRET//NF   the person who must not get in
#
# Act 1, honest DS:      (1) your client refuses   (2) the DS refuses
# Act 2, compromised DS: you force it and the DS sequences it anyway;
#                        (3) member's client detects the fork, freezes the room, reports it
#                        (4) friend's client refuses to join
#                        nobody can send; a steward closes the room.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p ds -p garble-cli
G=target/debug/garble
D=target/money-demo
rm -rf "$D" && mkdir -p "$D"

banner() { printf '\n\033[1;7m %s \033[0m\n' "$*"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
expect_denied() { if "$@"; then echo "!! expected a denial"; exit 1; else [ $? -eq 2 ] || exit 1; fi; }
PIDS=()
trap 'kill ${PIDS[@]} 2>/dev/null' EXIT

DS_BIN=target/debug/garble-ds
$G issuer init --out $D/issuer --log-key "$($DS_BIN keygen --key $D/ds-log.key 2>/dev/null)" >/dev/null

# act DIR PORT [ds flags…]: start a DS, enroll the three people, create the room.
setup() {
  local dir=$1 port=$2; shift 2
  local ds=http://127.0.0.1:$port
  target/debug/garble-ds --listen 127.0.0.1:$port --trust $D/issuer/trust.json --log-dir $dir/log --log-key $D/ds-log.key "$@" &
  PIDS+=($!)
  for _ in $(seq 50); do curl -s $ds/v1/log/checkpoint >/dev/null && break; sleep 0.1; done
  for u in you:'TS//SI//NF' member:'TS//SI//NF' friend:'S//NF'; do
    local user=${u%%:*} access=${u#*:}
    $G --home $dir/$user init --user $user --ds $ds --trust $D/issuer/trust.json >/dev/null
    $G issuer issue --issuer $D/issuer --user $user --key "$($G --home $dir/$user key)" \
       --access "$access" --out $dir/$user.cred.json >/dev/null
    $G --home $dir/$user enroll --credential $dir/$user.cred.json >/dev/null
    echo "enrolled $user ($access)"
  done
  $G --home $dir/you create-room ops --ceiling 'TS//SI//NF'
  $G --home $dir/you add ops member
  $G --home $dir/member read
}

banner "ACT 1: honest delivery service"
A=$D/act1; mkdir -p $A
setup $A 7781

step "(1) you add friend (SECRET) to a TS//SI room: your own client refuses"
expect_denied $G --home $A/you add ops friend

step "(2) you bypass your client: the delivery service refuses"
expect_denied $G --home $A/you add ops friend --skip-client-check

step "audit log"
$G --home $A/you log | grep -v 'session              opened' | tee $A/log.out

banner "ACT 2: compromised delivery service (--simulate-malicious) + colluding adder"
B=$D/act2; mkdir -p $B
setup $B 7782 --simulate-malicious

step "you force the add; the compromised DS sequences it"
$G --home $B/you add ops friend --skip-client-check

step "(3) member's client checks the commit itself: fork detected, room frozen, reported"
$G --home $B/member read | tee $B/member.out
grep -q 'FORK DETECTED' $B/member.out

step "(4) friend's client checks the Welcome against its own clearance: refuses to join"
$G --home $B/friend read | tee $B/friend.out
grep -q 'REFUSED TO JOIN' $B/friend.out

step "the room is frozen: member's client won't send, and the DS refuses you"
expect_denied $G --home $B/member send ops --marking 'TS//SI//NF' 'anyone?'
expect_denied $G --home $B/you send ops --marking 'TS//SI//NF' 'nothing to see here'

step "a steward closes the room after investigating"
$G --home $B/you clear-fork ops --note 'collusion confirmed; recreating without friend'
expect_denied $G --home $B/you send ops --marking 'TS//SI//NF' 'still closed?'

step "audit log"
$G --home $B/you log | grep -v 'session              opened' | tee $B/log.out
grep -q ' fork ' $B/log.out
grep -q 'fork-cleared' $B/log.out
echo; echo "money demo ok"
