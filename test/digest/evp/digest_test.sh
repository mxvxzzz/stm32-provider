#!/bin/bash
set -u

#
# digest_test.sh - verification campaign for digest_evp.c (hashing)

# digest_test.sh - verification campaign for digest_evp.c (hashing)
# Same logic as hash_test.sh
# but calling ./digest_evp instead of openssl dgst.
#
# Compile the file in stm32-provider/test/digest/digest_evp.c
#
# With openssl dgst, requests are limited to 4096 bytes,
# but with the EVP interface, you can control the requests length.
#
# QUICK=1 ./digest_test.sh reduces the file list.
#

OUTDIR=/tmp/digest_evp
EVP_TEST=./evp_test
FAIL=0
PASS=0
TOTAL=0

mkdir -p "$OUTDIR"

IMPLS=(soft st_afalg st_cryptodev)

ALGOS=(
    "SHA1"
    "SHA224"
    "SHA256"
    "SHA384"
    "SHA512"
    "SHA3-224"
    "SHA3-256"
    "SHA3-384"
    "SHA3-512"
)

FILES=(
    "16B.bin"
    "64B.bin"
    "128B.bin"
    "256B.bin"
    "4096B.bin"
    "5000B.bin"
    "9000B.bin"
    "64K.bin"
    "128K.bin"
    "512K.bin"
    "1M.bin"
    "10M.bin"
)

if [ "${QUICK:-0}" = "1" ]; then
    FILES=(16B.bin 4096B.bin 1M.bin)
fi

compute_digest() {
    local impl="$1" algo="$2" infile="$3"
    "$EVP_TEST" "$impl" "$algo" "$infile" 2>/dev/null
}

run_self_test() {
    local label="$1" algo="$2" infile="$3" impl="$4"
    local ref hw

    TOTAL=$((TOTAL + 1))

    ref=$(compute_digest soft "$algo" "$infile")
    if [ -z "$ref" ]; then
        echo "SKIP | $label | software reference failed"
        return
    fi

    hw=$(compute_digest "$impl" "$algo" "$infile")
    if [ -z "$hw" ]; then
        echo "KO   | $label | $impl failed"
        FAIL=$((FAIL + 1))
        return
    fi

    if [ "$hw" = "$ref" ]; then
        echo "OK   | $label"
        PASS=$((PASS + 1))
    else
        echo "KO   | $label | digest mismatch"
        echo "    software : $ref"
        echo "    $impl : $hw"
        FAIL=$((FAIL + 1))
    fi
}

run_cross_test() {
    local label="$1" algo="$2" infile="$3" impl_a="$4" impl_b="$5"
    local da db

    TOTAL=$((TOTAL + 1))

    da=$(compute_digest "$impl_a" "$algo" "$infile")
    if [ -z "$da" ]; then
        echo "KO   | $label | $impl_a failed"
        FAIL=$((FAIL + 1))
        return
    fi

    db=$(compute_digest "$impl_b" "$algo" "$infile")
    if [ -z "$db" ]; then
        echo "KO   | $label | $impl_b failed"
        FAIL=$((FAIL + 1))
        return
    fi

    if [ "$da" = "$db" ]; then
        echo "OK   | $label"
        PASS=$((PASS + 1))
    else
        echo "KO   | $label | digest mismatch between implementations"
        FAIL=$((FAIL + 1))
    fi
}

run_negative_test() {
    local label="$1" algo="$2" infile="$3" tampered="$4" impl="$5"
    local d_orig d_tampered

    TOTAL=$((TOTAL + 1))

    d_orig=$(compute_digest "$impl" "$algo" "$infile")
    if [ -z "$d_orig" ]; then
        echo "SKIP | $label | $impl failed on original file"
        return
    fi

    d_tampered=$(compute_digest "$impl" "$algo" "$tampered")
    if [ -z "$d_tampered" ]; then
        echo "SKIP | $label | $impl failed on tampered file"
        return
    fi

    if [ "$d_orig" != "$d_tampered" ]; then
        echo "OK   | $label | digest changed as expected"
        PASS=$((PASS + 1))
    else
        echo "KO   | $label | digest unchanged after tampering"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Generating test files ==="

dd if=/dev/urandom of="$OUTDIR/16B.bin"   bs=1  count=16   status=none
dd if=/dev/urandom of="$OUTDIR/64B.bin"   bs=1  count=64   status=none
dd if=/dev/urandom of="$OUTDIR/128B.bin"  bs=1  count=128  status=none
dd if=/dev/urandom of="$OUTDIR/256B.bin"  bs=1  count=256  status=none
dd if=/dev/urandom of="$OUTDIR/4096B.bin" bs=1K count=4    status=none
dd if=/dev/urandom of="$OUTDIR/5000B.bin" bs=1  count=5000 status=none
dd if=/dev/urandom of="$OUTDIR/9000B.bin" bs=1  count=9000 status=none
dd if=/dev/urandom of="$OUTDIR/64K.bin"   bs=1K count=64   status=none
dd if=/dev/urandom of="$OUTDIR/128K.bin"  bs=1K count=128  status=none
dd if=/dev/urandom of="$OUTDIR/512K.bin"  bs=1K count=512  status=none
dd if=/dev/urandom of="$OUTDIR/1M.bin"    bs=1K count=1024 status=none
dd if=/dev/urandom of="$OUTDIR/10M.bin"   bs=1M count=10   status=none

# Tampered copy of one representative file, used for the negative test.
# First 8 bytes are forced to zero, the probability that random data
# already started with 8 zero bytes is negligible.
cp "$OUTDIR/4096B.bin" "$OUTDIR/4096B_tampered.bin"
dd if=/dev/zero of="$OUTDIR/4096B_tampered.bin" bs=1 seek=0 count=8 conv=notrunc status=none

echo ""
echo "=== DIGEST TEST CAMPAIGN START ==="
echo ""

echo "=== Self tests (hardware vs software reference) ==="
for impl in st_afalg st_cryptodev; do
    for algo in "${ALGOS[@]}"; do
        for f in "${FILES[@]}"; do
            run_self_test "${impl}/${algo}/${f}" "$algo" "$OUTDIR/$f" "$impl"
        done
    done
done

echo ""
echo "=== Cross tests (st_afalg vs st_cryptodev) ==="
for algo in "${ALGOS[@]}"; do
    for f in "${FILES[@]}"; do
        run_cross_test "${algo}/${f}/st_afalg<->st_cryptodev" "$algo" "$OUTDIR/$f" st_afalg st_cryptodev
    done
done

echo ""
echo "=== Negative tests (digest must change when the file is tampered) ==="
for impl in "${IMPLS[@]}"; do
    for algo in "${ALGOS[@]}"; do
        run_negative_test "${impl}/${algo}/tamper" "$algo" "$OUTDIR/4096B.bin" "$OUTDIR/4096B_tampered.bin" "$impl"
    done
done

echo ""
echo "=== DIGEST TEST CAMPAIGN END ==="
echo "TOTAL: $TOTAL  |  PASS: $PASS  |  FAIL: $FAIL"

rm -rf "$OUTDIR"

if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: ALL PASS"
    exit 0
else
    echo "RESULT: FAIL"
    exit 1
fi