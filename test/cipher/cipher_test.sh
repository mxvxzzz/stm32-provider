#!/bin/bash
set -u

#
# cipher.sh - exhaustive cipher provider test campaign
#

OUTDIR=/tmp/cipher_campaign
FAIL=0
PASS=0
TOTAL=0

mkdir -p "$OUTDIR"

if [ -w /proc/sys/kernel/printk ]; then
    OLD_PRINTK=$(cat /proc/sys/kernel/printk)
    echo 1 4 1 7 > /proc/sys/kernel/printk
fi

# Providers to test
PROVIDER_A="pv_afalg"
PROVIDER_B="pv_cryptodev"

# Optional STM32 provider label if needed by your build
PROVIDER_STM32="stm32prov"

PROPQUERY="provider=stm32"

KEY128="2b7e151628aed2a6abf7158809cf4f3c"
KEY192="8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
KEY256="603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff5"
IV="000102030405060708090a0b0c0d0e0f"

FILES=(
    "empty.bin"
    "1byte.bin"
    "string.bin"
    "15B.bin"
    "16B.bin"
    "17B.bin"
    "32B.bin"
    "33B.bin"
    "1K.bin"
    "4K.bin"
    "4K_minus1.bin"
    "4K_plus1.bin"
    "32K.bin"
    "64K.bin"
    "100K.bin"
    "1M.bin"
)

MODES_IV="aes-128-cbc aes-192-cbc aes-256-cbc aes-128-ctr aes-192-ctr aes-256-ctr"
MODES_NOIV="aes-128-ecb aes-192-ecb aes-256-ecb"

get_key() {
    case "$1" in
        aes-128-*) echo "$KEY128" ;;
        aes-192-*) echo "$KEY192" ;;
        aes-256-*) echo "$KEY256" ;;
    esac
}

make_iv_opt() {
    if [ "$1" = "iv" ]; then
        echo "-iv $IV"
    else
        echo ""
    fi
}

run_encrypt() {
    local provider="$1"
    local mode="$2"
    local key="$3"
    local infile="$4"
    local outfile="$5"
    local use_iv="$6"
    local iv_opt
    iv_opt=$(make_iv_opt "$use_iv")

    if [ "$provider" = "soft" ]; then
        openssl enc -"$mode" -K "$key" $iv_opt -in "$infile" -out "$outfile" 2>/dev/null
    else
        openssl enc -"$mode" \
            -provider "$provider" -provider default \
            -propquery "$PROPQUERY" \
            -K "$key" $iv_opt \
            -in "$infile" -out "$outfile" 2>/dev/null
    fi
}

run_decrypt() {
    local provider="$1"
    local mode="$2"
    local key="$3"
    local infile="$4"
    local outfile="$5"
    local use_iv="$6"
    local iv_opt
    iv_opt=$(make_iv_opt "$use_iv")

    if [ "$provider" = "soft" ]; then
        openssl enc -d -"$mode" -K "$key" $iv_opt -in "$infile" -out "$outfile" 2>/dev/null
    else
        openssl enc -d -"$mode" \
            -provider "$provider" -provider default \
            -propquery "$PROPQUERY" \
            -K "$key" $iv_opt \
            -in "$infile" -out "$outfile" 2>/dev/null
    fi
}

compare_files() {
    diff -q "$1" "$2" >/dev/null 2>&1
}

run_test() {
    local label="$1"
    local mode="$2"
    local key="$3"
    local infile="$4"
    local use_iv="$5"
    local enc_provider="$6"
    local dec_provider="$7"

    local enc_file="$OUTDIR/enc.bin"
    local dec_file="$OUTDIR/dec.bin"
    local ref_enc="$OUTDIR/ref_enc.bin"
    local ref_dec="$OUTDIR/ref_dec.bin"

    TOTAL=$((TOTAL + 1))

    # Reference path: software encrypt/decrypt
    if ! run_encrypt "soft" "$mode" "$key" "$infile" "$ref_enc" "$use_iv"; then
        echo "SKIP | $label | software encrypt failed"
        return
    fi

    if ! run_decrypt "soft" "$mode" "$key" "$ref_enc" "$ref_dec" "$use_iv"; then
        echo "SKIP | $label | software decrypt failed"
        return
    fi

    if ! compare_files "$infile" "$ref_dec"; then
        echo "SKIP | $label | software self-check failed"
        return
    fi

    # Encrypt with selected provider
    if ! run_encrypt "$enc_provider" "$mode" "$key" "$infile" "$enc_file" "$use_iv"; then
        echo "KO   | $label | provider encrypt failed"
        FAIL=$((FAIL + 1))
        return
    fi

    # Decrypt with selected provider
    if ! run_decrypt "$dec_provider" "$mode" "$key" "$enc_file" "$dec_file" "$use_iv"; then
        echo "KO   | $label | provider decrypt failed"
        FAIL=$((FAIL + 1))
        return
    fi

    if compare_files "$infile" "$dec_file"; then
        echo "OK   | $label"
        PASS=$((PASS + 1))
    else
        echo "KO   | $label | plaintext mismatch after decrypt"
        FAIL=$((FAIL + 1))
    fi

    rm -f "$enc_file" "$dec_file" "$ref_enc" "$ref_dec"
}

run_cross_test() {
    local label="$1"
    local mode="$2"
    local key="$3"
    local infile="$4"
    local use_iv="$5"
    local enc_provider="$6"
    local dec_provider="$7"

    local enc_file="$OUTDIR/cross_enc.bin"
    local dec_file="$OUTDIR/cross_dec.bin"

    TOTAL=$((TOTAL + 1))

    if ! run_encrypt "$enc_provider" "$mode" "$key" "$infile" "$enc_file" "$use_iv"; then
        echo "KO   | $label | cross encrypt failed"
        FAIL=$((FAIL + 1))
        return
    fi

    if ! run_decrypt "$dec_provider" "$mode" "$key" "$enc_file" "$dec_file" "$use_iv"; then
        echo "KO   | $label | cross decrypt failed"
        FAIL=$((FAIL + 1))
        return
    fi

    if compare_files "$infile" "$dec_file"; then
        echo "OK   | $label"
        PASS=$((PASS + 1))
    else
        echo "KO   | $label | cross plaintext mismatch"
        FAIL=$((FAIL + 1))
    fi

    rm -f "$enc_file" "$dec_file"
}

run_negative_test() {
    local label="$1"
    local mode="$2"
    local key="$3"
    local infile="$4"
    local use_iv="$5"

    local enc_good="$OUTDIR/neg_good.bin"
    local dec_bad="$OUTDIR/neg_bad.bin"
    local bad_key="$6"
    local bad_iv="$7"
    local iv_opt_good=""
    local iv_opt_bad=""

    TOTAL=$((TOTAL + 1))

    if [ "$use_iv" = "iv" ]; then
        iv_opt_good="-iv $IV"
        iv_opt_bad="-iv $bad_iv"
    fi

    if ! openssl enc -"$mode" -K "$key" $iv_opt_good -in "$infile" -out "$enc_good" 2>/dev/null; then
        echo "SKIP | $label | negative setup encrypt failed"
        return
    fi

    if ! openssl enc -d -"$mode" -K "$bad_key" $iv_opt_bad -in "$enc_good" -out "$dec_bad" 2>/dev/null; then
        echo "OK   | $label | negative test failed as expected"
        PASS=$((PASS + 1))
        rm -f "$enc_good" "$dec_bad"
        return
    fi

    if compare_files "$infile" "$dec_bad"; then
        echo "KO   | $label | negative test unexpectedly matched"
        FAIL=$((FAIL + 1))
    else
        echo "OK   | $label | negative test produced different plaintext"
        PASS=$((PASS + 1))
    fi

    rm -f "$enc_good" "$dec_bad"
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

echo "=== Self tests: provider A and provider B ==="
for mode in $MODES_IV; do
    key=$(get_key "$mode")
    for f in "${FILES[@]}"; do
        [ "$f" = "empty.bin" ] && continue
        fpath="$OUTDIR/$f"
        run_test "${mode}/${f}/A" "$mode" "$key" "$fpath" "iv" "$PROVIDER_A" "$PROVIDER_A"
        run_test "${mode}/${f}/B" "$mode" "$key" "$fpath" "iv" "$PROVIDER_B" "$PROVIDER_B"
    done
done

for mode in $MODES_NOIV; do
    key=$(get_key "$mode")
    for f in "${FILES[@]}"; do
        [ "$f" = "empty.bin" ] && continue
        fpath="$OUTDIR/$f"
        run_test "${mode}/${f}/A" "$mode" "$key" "$fpath" "noiv" "$PROVIDER_A" "$PROVIDER_A"
        run_test "${mode}/${f}/B" "$mode" "$key" "$fpath" "noiv" "$PROVIDER_B" "$PROVIDER_B"
    done
done

echo ""
echo "=== Cross tests between providers ==="
for mode in $MODES_IV; do
    key=$(get_key "$mode")
    for f in "${FILES[@]}"; do
        [ "$f" = "empty.bin" ] && continue
        fpath="$OUTDIR/$f"
        run_cross_test "${mode}/${f}/A->B" "$mode" "$key" "$fpath" "iv" "$PROVIDER_A" "$PROVIDER_B"
        run_cross_test "${mode}/${f}/B->A" "$mode" "$key" "$fpath" "iv" "$PROVIDER_B" "$PROVIDER_A"
    done
done

for mode in $MODES_NOIV; do
    key=$(get_key "$mode")
    for f in "${FILES[@]}"; do
        [ "$f" = "empty.bin" ] && continue
        fpath="$OUTDIR/$f"
        run_cross_test "${mode}/${f}/A->B" "$mode" "$key" "$fpath" "noiv" "$PROVIDER_A" "$PROVIDER_B"
        run_cross_test "${mode}/${f}/B->A" "$mode" "$key" "$fpath" "noiv" "$PROVIDER_B" "$PROVIDER_A"
    done
done

echo ""
echo "=== Cross tests with software ==="
for mode in $MODES_IV; do
    key=$(get_key "$mode")
    for f in "${FILES[@]}"; do
        [ "$f" = "empty.bin" ] && continue
        fpath="$OUTDIR/$f"
        run_cross_test "${mode}/${f}/A->soft" "$mode" "$key" "$fpath" "iv" "$PROVIDER_A" "soft"
        run_cross_test "${mode}/${f}/B->soft" "$mode" "$key" "$fpath" "iv" "$PROVIDER_B" "soft"
        run_cross_test "${mode}/${f}/soft->A" "$mode" "$key" "$fpath" "iv" "soft" "$PROVIDER_A"
        run_cross_test "${mode}/${f}/soft->B" "$mode" "$key" "$fpath" "iv" "soft" "$PROVIDER_B"
    done
done

for mode in $MODES_NOIV; do
    key=$(get_key "$mode")
    for f in "${FILES[@]}"; do
        [ "$f" = "empty.bin" ] && continue
        fpath="$OUTDIR/$f"
        run_cross_test "${mode}/${f}/A->soft" "$mode" "$key" "$fpath" "noiv" "$PROVIDER_A" "soft"
        run_cross_test "${mode}/${f}/B->soft" "$mode" "$key" "$fpath" "noiv" "$PROVIDER_B" "soft"
        run_cross_test "${mode}/${f}/soft->A" "$mode" "$key" "$fpath" "noiv" "soft" "$PROVIDER_A"
        run_cross_test "${mode}/${f}/soft->B" "$mode" "$key" "$fpath" "noiv" "soft" "$PROVIDER_B"
    done
done

echo ""
echo "=== Negative tests ==="
BAD_KEY="ffffffffffffffffffffffffffffffff"
BAD_IV="11111111111111111111111111111111"

run_negative_test "aes-256-cbc/16B/bad-key" "aes-256-cbc" "$KEY256" "$OUTDIR/16B.bin" "iv" "$BAD_KEY" "$BAD_IV"
run_negative_test "aes-256-cbc/1K/bad-iv"   "aes-256-cbc" "$KEY256" "$OUTDIR/1K.bin"  "iv" "$KEY256"  "$BAD_IV"
run_negative_test "aes-256-ctr/4K/bad-key"  "aes-256-ctr" "$KEY256" "$OUTDIR/4K.bin"  "iv" "$BAD_KEY" "$BAD_IV"
run_negative_test "aes-256-ecb/32B/bad-key" "aes-256-ecb" "$KEY256" "$OUTDIR/32B.bin" "noiv" "$BAD_KEY" "$BAD_IV"

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