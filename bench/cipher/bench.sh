#!/bin/sh
set -eu

IMPL="${1:?Usage: $0 <impl> <seconds> <block1> [block2] ...}"
SECS="${2:?Usage: $0 <impl> <seconds> <block1> [block2] ...}"
shift 2
BLOCKS="$*"

OUTFILE="bench.json"

TMP_OUT="$(mktemp)"
TMP_CPU_BEFORE="$(mktemp)"
TMP_CPU_AFTER="$(mktemp)"
TMP_NEW="$(mktemp)"

cleanup() {
  rm -f "$TMP_OUT" "$TMP_CPU_BEFORE" "$TMP_CPU_AFTER" "$TMP_NEW"
}
trap cleanup EXIT

get_stat() {
  awk '/^cpu[0-9]+ / {
    idle=$5+$6
    total=0
    for (i=2;i<=NF;i++) total+=$i
    printf "%s %s %s\n",$1,total,idle
  }' /proc/stat
}

build_cmd() {
  algo="$1"
  case "$IMPL" in
    soft)
      echo "openssl speed -seconds $SECS -evp $algo -bytes $BYTES"
      ;;
    pv_afalg)
      echo "openssl speed -provider pv_afalg -provider default -propquery \"provider=stm32\" -seconds $SECS -evp $algo -bytes $BYTES"
      ;;
    pv_cryptodev)
      echo "openssl speed -provider pv_cryptodev -provider default -propquery \"provider=stm32\" -seconds $SECS -evp $algo -bytes $BYTES"
      ;;
    eng_afalg)
      echo "openssl speed -engine afalg -seconds $SECS -evp $algo -bytes $BYTES"
      ;;
    eng_cryptodev)
      echo "openssl speed -engine devcrypto -seconds $SECS -evp $algo -bytes $BYTES"
      ;;
    *)
      echo "Unknown impl: $IMPL" >&2
      exit 1
      ;;
  esac
}

run_algo() {
  algo="$1"
  cmd=$(build_cmd "$algo")

  get_stat > "$TMP_CPU_BEFORE"
  sh -c "$cmd" > "$TMP_OUT" 2>/dev/null || return 1
  get_stat > "$TMP_CPU_AFTER"

  kbps=$(awk -v a="$algo" '
    BEGIN { IGNORECASE=1 }
    $1 ~ a {
      val=$2
      gsub(/k$/, "", val)
      print val
      found=1
    }
    END { if (!found) exit 1 }
  ' "$TMP_OUT") || return 1

  mbps=$(awk -v k="$kbps" 'BEGIN { printf "%.2f", k/1000.0 }')

  cpu0=$(paste "$TMP_CPU_BEFORE" "$TMP_CPU_AFTER" | awk '/cpu0/{
    dtotal=$5-$2
    didle=$6-$3
    if (dtotal>0) printf "%.2f", 100*(1-didle/dtotal)
  }')

  cpu1=$(paste "$TMP_CPU_BEFORE" "$TMP_CPU_AFTER" | awk '/cpu1/{
    dtotal=$5-$2
    didle=$6-$3
    if (dtotal>0) printf "%.2f", 100*(1-didle/dtotal)
  }')

  printf '"%s": {"kbps": %s, "mbps": %s, "cpu0": %s, "cpu1": %s}' \
    "$algo" \
    "${kbps:-0}" "${mbps:-0}" \
    "${cpu0:-0}" "${cpu1:-0}"
}

case "$IMPL" in
  eng_afalg)
    ALGOS="aes-128-cbc aes-192-cbc aes-256-cbc"
    ;;
  *)
    ALGOS="aes-128-cbc aes-192-cbc aes-256-cbc aes-128-ctr aes-192-ctr aes-256-ctr aes-128-ecb aes-192-ecb aes-256-ecb"
    ;;
esac

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
block_entries=""
first_block=1

for BYTES in $BLOCKS; do
  echo ""
  echo "▶  bloc=${BYTES}B  impl=${IMPL}  seconds=${SECS}"

  algo_entries=""
  first_algo=1

  for algo in $ALGOS; do
    json_algo=$(run_algo "$algo") || json_algo=""
    if [ "$first_algo" -eq 1 ]; then
      algo_entries="$json_algo"
      first_algo=0
    else
      algo_entries="$algo_entries,$json_algo"
    fi
  done

  entry=$(printf '{
    "block_bytes": %s,
    %s
  }' "$BYTES" "$algo_entries")

  if [ "$first_block" -eq 1 ]; then
    block_entries="$entry"
    first_block=0
  else
    block_entries="$block_entries,$entry"
  fi
done

new_run=$(printf '{
  "implementation": "%s",
  "timestamp": "%s",
  "seconds_per_run": %s,
  "blocks": [%s]
}' "$IMPL" "$TIMESTAMP" "$SECS" "$block_entries")

printf '%s' "$new_run" > "$TMP_NEW"

python3 -c "
import json

outfile = 'bench.json'
newfile = '$TMP_NEW'

with open(newfile) as f:
    new_entry = json.load(f)

try:
    with open(outfile) as f:
        data = json.load(f)
except:
    data = []

match = None
for e in data:
    if e.get('implementation') == new_entry['implementation']:
        match = e
        break

if match is None:
    data.append(new_entry)
else:
    for nb in new_entry['blocks']:
        match['blocks'] = [b for b in match['blocks'] if b.get('block_bytes') != nb['block_bytes']]
        match['blocks'].append(nb)
    match['timestamp'] = new_entry['timestamp']

with open(outfile, 'w') as f:
    json.dump(data, f, indent=2)
"

echo ""
echo "out : $OUTFILE"