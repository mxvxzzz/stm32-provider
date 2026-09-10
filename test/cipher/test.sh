#!/bin/bash
set -u

PROVIDER="stm32prov"
PROPQUERY="provider=stm32"
OUTDIR=/tmp/cipher_campaign
FAIL=0
PASS=0
TOTAL=0

mkdir -p "$OUTDIR"

if [ -w /proc/sys/kernel/printk ]; then
    OLD_PRINTK=$(cat /proc/sys/kernel/printk)
    echo 1 4 1 7 > /proc/sys/kernel/printk
fi

KEY128="2b7e151628aed2a6abf7158809cf4f3c"
KEY192="8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
KEY256="603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff5"
IV="000102030405060708090a0b0c0d0e0f"

run_test() {
    local label="$1"
    local mode="$2"
    local key="$3"
    local infile="$4"
    local use_iv="$5"

    local enc_file="$OUTDIR/enc.bin"
    local dec_file="$OUTDIR/dec.bin"
    local ref_enc="$OUTDIR/ref_enc.bin"
    local ref_dec="$OUTDIR/ref_dec.bin"
    local iv_opt=""
    local prov_iv_opt=""

    TOTAL=$((TOTAL + 1))

    if [ "$use_iv" = "iv" ]; then
        iv_opt="-iv $IV"
        prov_iv_opt="-iv $IV"
    fi

    if ! openssl enc -"$mode" -K "$key" $iv_opt \
            -in "$infile" -out "$ref_enc" 2>/dev/null; then
        echo "SKIP | $label | default encrypt failed"
        return
    fi

    if ! openssl enc -d -"$mode" -K "$key" $iv_opt \
            -in "$ref_enc" -out "$ref_dec" 2>/dev/null; then
        echo "SKIP | $label | default decrypt failed"
        return
    fi

    if ! diff -q "$infile" "$ref_dec" >/dev/null 2>&1; then
        echo "SKIP | $label | default self-check failed"
        return
    fi

    if ! openssl enc -"$mode" \
            -provider "$PROVIDER" -provider default \
            -propquery "$PROPQUERY" \
            -K "$key" $prov_iv_opt \
            -in "$infile" -out "$enc_file" 2>/dev/null; then
        echo "KO   | $label | provider encrypt failed"
        FAIL=$((FAIL + 1))
        return
    fi

    if ! diff -q "$enc_file" "$ref_enc" >/dev/null 2>&1; then
        echo "KO   | $label | ciphertext mismatch"
        FAIL=$((FAIL + 1))
        return
    fi

    if ! openssl enc -d -"$mode" \
            -provider "$PROVIDER" -provider default \
            -propquery "$PROPQUERY" \
            -K "$key" $prov_iv_opt \
            -in "$enc_file" -out "$dec_file" 2>/dev/null; then
        echo "KO   | $label | provider decrypt failed"
        FAIL=$((FAIL + 1))
        return
    fi

    if diff -q "$infile" "$dec_file" >/dev/null 2>&1; then
        echo "OK   | $label"
        PASS=$((PASS + 1))
    else
        echo "KO   | $label | plaintext mismatch after decrypt"
        FAIL=$((FAIL + 1))
    fi

    rm -f "$enc_file" "$dec_file" "$ref_enc" "$ref_dec"
}

echo "=== Generating test files ==="

touch "$OUTDIR/empty.bin"
printf "A" > "$OUTDIR/1byte.bin"
echo -n "Hello STM32MP25 cipher test!" > "$OUTDIR/string.bin"

dd if=/dev/urandom of="$OUTDIR/16B.bin" bs=16 count=1 status=none
dd if=/dev/urandom of="$OUTDIR/15B.bin" bs=1 count=15 status=none
dd if=/dev/urandom of="$OUTDIR/17B.bin" bs=1 count=17 status=none
dd if=/dev/urandom of="$OUTDIR/32B.bin" bs=32 count=1 status=none
dd if=/dev/urandom of="$OUTDIR/33B.bin" bs=1 count=33 status=none
dd if=/dev/urandom of="$OUTDIR/1K.bin" bs=1K count=1 status=none
dd if=/dev/urandom of="$OUTDIR/4K.bin" bs=1K count=4 status=none
dd if=/dev/urandom of="$OUTDIR/4K_minus1.bin" bs=1 count=4095 status=none
dd if=/dev/urandom of="$OUTDIR/4K_plus1.bin" bs=1 count=4097 status=none
dd if=/dev/urandom of="$OUTDIR/32K.bin" bs=1K count=32 status=none
dd if=/dev/urandom of="$OUTDIR/64K.bin" bs=1K count=64 status=none
dd if=/dev/urandom of="$OUTDIR/100K.bin" bs=1K count=100 status=none
dd if=/dev/urandom of="$OUTDIR/1M.bin" bs=1K count=1024 status=none

echo ""
echo "=== CIPHER TEST START ==="
echo ""

MODES_IV="aes-128-cbc aes-192-cbc aes-256-cbc aes-128-ctr aes-192-ctr aes-256-ctr"
MODES_NOIV="aes-128-ecb aes-192-ecb aes-256-ecb"

get_key() {
    case "$1" in
        aes-128-*) echo "$KEY128" ;;
        aes-192-*) echo "$KEY192" ;;
        aes-256-*) echo "$KEY256" ;;
    esac
}

FILES="empty.bin 1byte.bin string.bin 15B.bin 16B.bin 17B.bin 32B.bin 33B.bin 1K.bin 4K.bin 4K_minus1.bin 4K_plus1.bin 32K.bin 64K.bin 100K.bin 1M.bin"

for mode in $MODES_IV; do
    key=$(get_key "$mode")
    echo "--- $mode ---"
    for f in $FILES; do
        fpath="$OUTDIR/$f"
        if [ "$f" = "empty.bin" ]; then
            continue
        fi
        run_test "${mode}/${f}" "$mode" "$key" "$fpath" "iv"
    done
    echo ""
done

for mode in $MODES_NOIV; do
    key=$(get_key "$mode")
    echo "--- $mode ---"
    for f in $FILES; do
        fpath="$OUTDIR/$f"
        if [ "$f" = "empty.bin" ]; then
            continue
        fi
        run_test "${mode}/${f}" "$mode" "$key" "$fpath" "noiv"
    done
    echo ""
done

echo "--- non-aligned sizes (CBC-256) ---"
for i in $(seq 1 30); do
    size=$(( (i * 4096) + (i % 7) ))
    stress_file="$OUTDIR/stress_${i}_${size}.bin"
    dd if=/dev/urandom of="$stress_file" bs=1 count="$size" status=none
    run_test "cbc256/stress_${size}B" "aes-256-cbc" "$KEY256" "$stress_file" "iv"
    rm -f "$stress_file"
done
echo ""

echo "--- non-aligned sizes (CTR-256) ---"
for i in $(seq 1 30); do
    size=$(( (i * 4096) + (i % 7) ))
    stress_file="$OUTDIR/stress_ctr_${i}_${size}.bin"
    dd if=/dev/urandom of="$stress_file" bs=1 count="$size" status=none
    run_test "ctr256/stress_${size}B" "aes-256-ctr" "$KEY256" "$stress_file" "iv"
    rm -f "$stress_file"
done
echo ""

echo "--- non-aligned sizes (ECB-256) ---"
for i in $(seq 1 30); do
    size=$(( (i * 4096) + (i % 7) ))
    stress_file="$OUTDIR/stress_ecb_${i}_${size}.bin"
    dd if=/dev/urandom of="$stress_file" bs=1 count="$size" status=none
    run_test "ecb256/stress_${size}B" "aes-256-ecb" "$KEY256" "$stress_file" "noiv"
    rm -f "$stress_file"
done
echo ""

echo "=== CIPHER TEST END ==="
echo "TOTAL: $TOTAL  |  PASS: $PASS  |  FAIL: $FAIL"

if [ -n "${OLD_PRINTK:-}" ] && [ -w /proc/sys/kernel/printk ]; then
    echo "$OLD_PRINTK" > /proc/sys/kernel/printk
fi

rm -rf "$OUTDIR"

if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: ALL PASS"
    exit 0
else
    echo "RESULT: FAIL"
    exit 1
fi