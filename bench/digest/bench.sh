#!/bin/sh
set -eu

IMPL="${1:?Usage: $0 <impl> <seconds> <block1> [block2] ...}"
SECS="${2:?Usage: $0 <impl> <seconds> <block1> [block2] ...}"
shift 2
BLOCKS="$*"
OUTFILE="bench.json"

build_cmd() {
  local bytes="$1"
  local algo="$2"
  case "$IMPL" in
    st_afalg)
      echo "taskset -c 0 ./evp_bench st_afalg $SECS $bytes $algo" ;;
    st_cryptodev)
      echo "taskset -c 0 ./evp_bench st_cryptodev $SECS $bytes $algo" ;;
    *)
      echo "Unknown impl: $IMPL" >&2; exit 1 ;;
  esac
}

get_stat() {
  awk '/^cpu[0-9]+ / {
    idle=$5+$6; total=0
    for (i=2;i<=NF;i++) total+=$i
    printf "%s %s %s\n",$1,total,idle
  }' /proc/stat
}

run_algo() {
  local bytes="$1"
  local algo="$2"
  local tmp_speed tmp_before tmp_after
  tmp_speed=$(mktemp)
  tmp_before=$(mktemp); tmp_after=$(mktemp)

  get_stat > "$tmp_before"

  CMD=$(build_cmd "$bytes" "$algo")
  sh -c "$CMD" > "$tmp_speed" 2>/dev/null

  get_stat > "$tmp_after"

  kbps=$(awk '/^'"$algo"'/ {
    val=$2; gsub(/k$/,"",val); printf "%.2f", val+0
  }' "$tmp_speed")

  # CPU usage per core
  cpu0=$(paste "$tmp_before" "$tmp_after" | awk '/cpu0/{dtotal=$5-$2;didle=$6-$3;if(dtotal>0)printf "%.2f",100*(1-didle/dtotal)}')
  cpu1=$(paste "$tmp_before" "$tmp_after" | awk '/cpu1/{dtotal=$5-$2;didle=$6-$3;if(dtotal>0)printf "%.2f",100*(1-didle/dtotal)}')

  mbps=$(echo "$kbps" | awk '{printf "%.2f", $1/1000}')

  printf '"%s": {"kbps": %s, "mbps": %s, "cpu0": %s, "cpu1": %s}' \
    "$algo" \
    "${kbps:-0}" "${mbps:-0}" \
    "${cpu0:-0}" "${cpu1:-0}"

  rm -f "$tmp_speed" "$tmp_before" "$tmp_after"
}

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
block_entries=""
first_block=1

for BYTES in $BLOCKS; do
  echo ""
  echo "▶  bloc=${BYTES}B  impl=${IMPL}  seconds=${SECS}"

  sha1_json=$(run_algo   "$BYTES" "sha1");   sleep 1
  sha256_json=$(run_algo "$BYTES" "sha256"); sleep 1
  sha512_json=$(run_algo "$BYTES" "sha512")

  entry=$(printf '{
      "block_bytes": %s,
      %s,
      %s,
      %s
    }' "$BYTES" "$sha1_json" "$sha256_json" "$sha512_json")

  if [ "$first_block" -eq 1 ]; then
    block_entries="$entry"; first_block=0
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

printf '%s' "$new_run" > "${OUTFILE}.new"

python3 -c "
import sys, json
with open('${OUTFILE}.new') as f:
    new_entry = json.load(f)
try:
    with open('$OUTFILE') as f:
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
with open('$OUTFILE', 'w') as f:
    json.dump(data, f, indent=2)
"

rm -f "${OUTFILE}.new"
echo ""
echo "out : $OUTFILE"