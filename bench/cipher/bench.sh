#!/bin/sh
set -eu

#──────────────────────────────────────────────────────────────────────────
# bench.sh · Benchmark AES (CBC/ECB/CTR, 128/192/256)
# Usage: ./bench.sh <impl> <seconds> <block1> [block2] …
# impl  : soft | pv_afalg | pv_cryptodev | eng_afalg | eng_cryptodev
#──────────────────────────────────────────────────────────────────────────

IMPL="${1:?Usage: $0 <impl> <seconds> <block1> [block2] ...}"
SECS="${2:?Usage: $0 <impl> <seconds> <block1> [block2] ...}"
shift 2
BLOCKS="$*"

OUTFILE="bench.json"

TMP_OUT="$(mktemp)"
TMP_ERR="$(mktemp)"
TMP_CPU_BEFORE="$(mktemp)"
TMP_CPU_AFTER="$(mktemp)"
TMP_RUN="$(mktemp)"

cleanup() {
    rm -f "$TMP_OUT" "$TMP_ERR" "$TMP_CPU_BEFORE" "$TMP_CPU_AFTER" "$TMP_RUN"
}
trap cleanup EXIT

get_stat() {
    awk '/^cpu[0-9]+ / {
        idle = $5 + $6
        total = 0
        for (i = 2; i <= NF; i++) total += $i
        printf "%s %s %s\n", $1, total, idle
    }' /proc/stat
}

# eng_afalg ne supporte que CBC (moteur historique, pas de support ECB/CTR)

get_algos() {
    case "$1" in
        eng_afalg)
            echo "aes-128-cbc aes-192-cbc aes-256-cbc"
            ;;
        soft|pv_afalg|pv_cryptodev|eng_cryptodev)
            echo "aes-128-cbc aes-192-cbc aes-256-cbc aes-128-ctr aes-192-ctr aes-256-ctr aes-128-ecb aes-192-ecb aes-256-ecb"
            ;;
        *)
            echo "Unknown impl: $1" >&2
            exit 1
            ;;
    esac
}

# ── Exécute un algo, retourne un objet JSON {"algo":…} ─────────────────

run_algo() {
    algo="$1"
    max_attempts=3
    attempt=1

    while [ "$attempt" -le "$max_attempts" ]; do
        get_stat > "$TMP_CPU_BEFORE"

        case "$IMPL" in
            soft)
                openssl speed -seconds "$SECS" -evp "$algo" -bytes "$BYTES" > "$TMP_OUT" 2> "$TMP_ERR"
                ;;
            pv_afalg)
                openssl speed -provider pv_afalg -provider default -propquery "provider=stm32" -seconds "$SECS" -evp "$algo" -bytes "$BYTES" > "$TMP_OUT" 2> "$TMP_ERR"
                ;;
            pv_cryptodev)
                openssl speed -provider pv_cryptodev -provider default -propquery "provider=stm32" -seconds "$SECS" -evp "$algo" -bytes "$BYTES" > "$TMP_OUT" 2> "$TMP_ERR"
                ;;
            eng_afalg)
                openssl speed -engine afalg -seconds "$SECS" -evp "$algo" -bytes "$BYTES" > "$TMP_OUT" 2> "$TMP_ERR"
                ;;
            eng_cryptodev)
                openssl speed -engine devcrypto -seconds "$SECS" -evp "$algo" -bytes "$BYTES" > "$TMP_OUT" 2> "$TMP_ERR"
                ;;
            *)
                echo "Unknown impl: $IMPL" >&2
                return 1
                ;;
        esac

        get_stat > "$TMP_CPU_AFTER"

        kbps=$(awk -v a="$algo" '
        {
            if (tolower($1) == tolower(a)) {
                val = $2
                gsub(/k$/, "", val)
                print val
                exit
            }
        }
        ' "$TMP_OUT")

        case "$kbps" in
            ''|*[!0-9.]*|inf|INF|infinity|INFINITY)
                echo "  ! tentative $attempt/$max_attempts non exploitable pour $algo ($IMPL)" >&2
                echo "  ! stdout dans $TMP_OUT" >&2
                echo "  ! stderr dans $TMP_ERR" >&2
                attempt=$((attempt + 1))
                sleep 1
                continue
                ;;
        esac

        mbps=$(awk -v k="$kbps" 'BEGIN { printf "%.2f", k / 1000.0 }')

        cpu0=$(paste "$TMP_CPU_BEFORE" "$TMP_CPU_AFTER" | awk '/cpu0/{
            dtotal = $5 - $2
            didle  = $6 - $3
            if (dtotal > 0) printf "%.2f", 100 * (1 - didle / dtotal)
        }')

        cpu1=$(paste "$TMP_CPU_BEFORE" "$TMP_CPU_AFTER" | awk '/cpu1/{
            dtotal = $5 - $2
            didle  = $6 - $3
            if (dtotal > 0) printf "%.2f", 100 * (1 - didle / dtotal)
        }')

        printf '{"algo":"%s","kbps":%s,"mbps":%s,"cpu0":%s,"cpu1":%s}' \
            "$algo" "$kbps" "$mbps" "${cpu0:-0}" "${cpu1:-0}"
        return 0
    done

    echo "  ! échec final pour $algo après $max_attempts tentatives" >&2
    return 1
}

# ── Boucle principale : blocs × algos ────────────────────────────────────

ALGOS=$(get_algos "$IMPL")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

block_entries=""
first_block=1

for BYTES in $BLOCKS; do
    echo ""
    echo "▶  bloc=${BYTES}B  impl=${IMPL}  seconds=${SECS}"

    algo_entries=""
    first_algo=1

    for algo in $ALGOS; do
        if json_algo=$(run_algo "$algo"); then
            if [ "$first_algo" -eq 1 ]; then
                algo_entries="$json_algo"
                first_algo=0
            else
                algo_entries="$algo_entries,$json_algo"
            fi
        else
            echo "SKIP | $IMPL | ${BYTES}B | $algo" >&2
        fi
    done

    if [ -z "$algo_entries" ]; then
        echo "SKIP | $IMPL | ${BYTES}B | aucun algo n'a réussi" >&2
        continue
    fi

    entry=$(printf '{"block_bytes":%s,"results":[%s]}' "$BYTES" "$algo_entries")

    if [ "$first_block" -eq 1 ]; then
        block_entries="$entry"
        first_block=0
    else
        block_entries="$block_entries,$entry"
    fi
done

if [ -z "$block_entries" ]; then
    echo "Aucun résultat pour $IMPL, rien à écrire." >&2
    exit 1
fi

printf '{"implementation":"%s","timestamp":"%s","seconds_per_run":%s,"blocks":[%s]}' \
    "$IMPL" "$TIMESTAMP" "$SECS" "$block_entries" > "$TMP_RUN"
# ── Fusion dans bench.json (merge par implementation, par block_bytes) ──

python3 - "$OUTFILE" "$TMP_RUN" <<'PY'
import json
import sys
from pathlib import Path

outfile = Path(sys.argv[1])
newfile = Path(sys.argv[2])

with newfile.open() as f:
    new_entry = json.load(f)

if outfile.exists():
    try:
        with outfile.open() as f:
            data = json.load(f)
    except json.JSONDecodeError:
        data = []
else:
    data = []

if not isinstance(data, list):
    data = [data]

match = None
for e in data:
    if e.get("implementation") == new_entry["implementation"]:
        match = e
        break

if match is None:
    data.append(new_entry)
else:
    existing = {b.get("block_bytes"): b for b in match.get("blocks", [])}
    for nb in new_entry.get("blocks", []):
        existing[nb.get("block_bytes")] = nb
    match["blocks"] = [existing[k] for k in sorted(existing)]
    match["timestamp"] = new_entry["timestamp"]
    match["seconds_per_run"] = new_entry["seconds_per_run"]

with outfile.open("w") as f:
    json.dump(data, f, indent=2)
PY

echo ""
echo "out : $OUTFILE"