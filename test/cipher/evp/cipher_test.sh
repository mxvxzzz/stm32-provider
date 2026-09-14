#!/bin/bash
set -u

#
# cipher_test.sh - verification campaign for cipher_evp.c (encryption/decryption)
# Same logic as cipher_test.sh (self test, cross test, negative test)
# but calling ./evp_test instead of openssl enc.
#
# Compile the file in stm32-provider/test/cipher/cipher_evp.c
#
# With openssl enc, requests are limited to 4096 bytes,
# but with the EVP interface, you can control the requests length.
#
# QUICK=1 ./cipher_test.sh reduces the file list.
#

OUTDIR=/tmp/cipher_evp
EVP_TEST=./evp_test
FAIL=0
PASS=0
TOTAL=0

mkdir -p "$OUTDIR"

if [ -w /proc/sys/kernel/printk ]; then
    OLD_PRINTK=$(cat /proc/sys/kernel/printk)
    echo 1 4 1 7 > /proc/sys/kernel/printk
fi

IMPLS=(soft stm32prov pv_afalg pv_cryptodev eng_afalg eng_cryptodev)

KEY128="2b7e151628aed2a6abf7158809cf4f3c"
KEY192="8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
KEY256="603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff5"
IV="000102030405060708090a0b0c0d0e0f"

BAD_KEY128="ffffffffffffffffffffffffffffffff"
BAD_KEY192="ffffffffffffffffffffffffffffffffffffffffffffff"
BAD_KEY256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
BAD_IV="ffffffffffffffffffffffffffffffff"

FILES=(
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
    "128K.bin"
    "256K.bin"
    "307K.bin"
    "611K.bin"
    "1M.bin"
)

if [ "${QUICK:-0}" = "1" ]; then
    FILES=(16B.bin 1K.bin 64K.bin 1M.bin)
fi

MODES_IV="aes-128-cbc aes-192-cbc aes-256-cbc aes-128-ctr aes-192-ctr aes-256-ctr"
MODES_NOIV="aes-128-ecb aes-192-ecb aes-256-ecb"

get_key() {
    case "$1" in
        aes-128-*) echo "$KEY128" ;;
        aes-192-*) echo "$KEY192" ;;
        aes-256-*) echo "$KEY256" ;;
    esac
}

get_bad_key() {
    case "$1" in
        aes-128-*) echo "$BAD_KEY128" ;;
        aes-192-*) echo "$BAD_KEY192" ;;
        aes-256-*) echo "$BAD_KEY256" ;;
    esac
}

get_iv_arg() {
    if [ "$1" = "iv" ]; then
        echo "$IV"
    else
        echo "-"
    fi
}

run_encrypt() {
    local impl="$1" mode="$2" key="$3" infile="$4" outfile="$5" use_iv="$6"
    local iv_arg
    iv_arg=$(get_iv_arg "$use_iv")
    "$EVP_TEST" "$impl" enc "$mode" "$key" "$iv_arg" "$infile" "$outfile" 2>/dev/null
}

run_decrypt() {
    local impl="$1" mode="$2" key="$3" infile="$4" outfile="$5" use_iv="$6"
    local iv_arg
    iv_arg=$(get_iv_arg "$use_iv")
    "$EVP_TEST" "$impl" dec "$mode" "$key" "$iv_arg" "$infile" "$outfile" 2>/dev/null
}

compare_files() {
    diff -q "$1" "$2" >/dev/null 2>&1
}

run_test() {
    local label="$1" mode="$2" key="$3" infile="$4" use_iv="$5" impl="$6"

    local enc_file="$OUTDIR/enc.bin"
    local dec_file="$OUTDIR/dec.bin"

    TOTAL=$((TOTAL + 1))

    if ! run_encrypt "$impl" "$mode" "$key" "$infile" "$enc_file" "$use_iv"; then
        echo "KO   | $label | encrypt failed"
        FAIL=$((FAIL + 1))
        return
    fi

    if ! run_decrypt "$impl" "$mode" "$key" "$enc_file" "$dec_file" "$use_iv"; then
        echo "KO   | $label | decrypt failed"
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

    rm -f "$enc_file" "$dec_file"
}

run_cross_test() {
    local label="$1" mode="$2" key="$3" infile="$4" use_iv="$5" enc_impl="$6" dec_impl="$7"

    local enc_file="$OUTDIR/cross_enc.bin"
    local dec_file="$OUTDIR/cross_dec.bin"

    TOTAL=$((TOTAL + 1))

    if ! run_encrypt "$enc_impl" "$mode" "$key" "$infile" "$enc_file" "$use_iv"; then
        echo "KO   | $label | cross encrypt failed"
        FAIL=$((FAIL + 1))
        return
    fi

    if ! run_decrypt "$dec_impl" "$mode" "$key" "$enc_file" "$dec_file" "$use_iv"; then
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
    local label="$1" mode="$2" key="$3" infile="$4" use_iv="$5" bad_key="$6" bad_iv="$7" impl="${8:-soft}"

    local enc_good="$OUTDIR/neg_good.bin"
    local dec_bad="$OUTDIR/neg_bad.bin"
    local iv_arg_good iv_arg_bad

    TOTAL=$((TOTAL + 1))

    iv_arg_good=$(get_iv_arg "$use_iv")
    if [ "$use_iv" = "iv" ]; then
        iv_arg_bad="$bad_iv"
    else
        iv_arg_bad="-"
    fi

    if ! "$EVP_TEST" "$impl" enc "$mode" "$key" "$iv_arg_good" "$infile" "$enc_good" 2>/dev/null; then
        echo "SKIP | $label | negative setup encrypt failed"
        return
    fi

    if ! "$EVP_TEST" "$impl" dec "$mode" "$bad_key" "$iv_arg_bad" "$enc_good" "$dec_bad" 2>/dev/null; then
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
dd if=/dev/urandom of="$OUTDIR/128K.bin" bs=1K count=128 status=none
dd if=/dev/urandom of="$OUTDIR/256K.bin" bs=1K count=256 status=none
dd if=/dev/urandom of="$OUTDIR/307K.bin" bs=1K count=307 status=none
dd if=/dev/urandom of="$OUTDIR/611K.bin" bs=1K count=611 status=none
dd if=/dev/urandom of="$OUTDIR/1M.bin" bs=1K count=1024 status=none

echo ""
echo "=== EVP TEST CAMPAIGN START ==="
echo ""

echo "=== Self tests (chaque implementation seule) ==="
for impl in "${IMPLS[@]}"; do
    for mode in $MODES_IV; do
        key=$(get_key "$mode")
        for f in "${FILES[@]}"; do
            run_test "${impl}/${mode}/${f}" "$mode" "$key" "$OUTDIR/$f" "iv" "$impl"
        done
    done
    for mode in $MODES_NOIV; do
        key=$(get_key "$mode")
        for f in "${FILES[@]}"; do
            run_test "${impl}/${mode}/${f}" "$mode" "$key" "$OUTDIR/$f" "noiv" "$impl"
        done
    done
done

echo ""
echo "=== Cross tests (toutes les paires d implementations) ==="
for enc_impl in "${IMPLS[@]}"; do
    for dec_impl in "${IMPLS[@]}"; do
        [ "$enc_impl" = "$dec_impl" ] && continue
        for mode in $MODES_IV; do
            key=$(get_key "$mode")
            for f in "${FILES[@]}"; do
                run_cross_test "${mode}/${f}/${enc_impl}->${dec_impl}" "$mode" "$key" "$OUTDIR/$f" "iv" "$enc_impl" "$dec_impl"
            done
        done
        for mode in $MODES_NOIV; do
            key=$(get_key "$mode")
            for f in "${FILES[@]}"; do
                run_cross_test "${mode}/${f}/${enc_impl}->${dec_impl}" "$mode" "$key" "$OUTDIR/$f" "noiv" "$enc_impl" "$dec_impl"
            done
        done
    done
done

echo ""
echo "=== Negative tests ==="
for impl in "${IMPLS[@]}"; do
    run_negative_test "${impl}/aes-256-cbc/16B/bad-key" "aes-256-cbc" "$KEY256" "$OUTDIR/16B.bin" "iv" "$(get_bad_key aes-256-cbc)" "$BAD_IV" "$impl"
    run_negative_test "${impl}/aes-256-cbc/1K/bad-iv"   "aes-256-cbc" "$KEY256" "$OUTDIR/1K.bin"  "iv" "$KEY256"                        "$BAD_IV" "$impl"
    run_negative_test "${impl}/aes-256-ctr/4K/bad-key"  "aes-256-ctr" "$KEY256" "$OUTDIR/4K.bin"  "iv" "$(get_bad_key aes-256-ctr)" "$BAD_IV" "$impl"
    run_negative_test "${impl}/aes-256-ecb/32B/bad-key" "aes-256-ecb" "$KEY256" "$OUTDIR/32B.bin" "noiv" "$(get_bad_key aes-256-ecb)" "$BAD_IV" "$impl"
done

echo ""
echo "=== EVP TEST CAMPAIGN END ==="
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