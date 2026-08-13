#!/bin/bash
set -u

##############################################################################
#
#  test_stmaead.sh - execute tests for stmaead tool (AEAD)
#     
#  Usage :
#    ./test_stmaead.sh <provider>
#    ./test_stmaead.sh stm32prov
#    ./test_stmaead.sh stm32prov
#
##############################################################################

if [ $# -lt 1 ]; then
    echo "Usage: $0 <provider>  (stm32prov)"
    exit 1
fi

PROVIDER="$1"
TOOL="./stmaead"
DIR="/tmp/aead_test"
PASS=0
FAIL=0
SKIP=0
TOTAL=0

mkdir -p "$DIR"

if [ -w /proc/sys/kernel/printk ]; then
    OLD_PRINTK=$(cat /proc/sys/kernel/printk)
    echo 1 4 1 7 > /proc/sys/kernel/printk
fi

# Keys (hex)
K128="2b7e151628aed2a6abf7158809cf4f3c"
K192="8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
K256="603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff5"
AAD="48656c6c6f20776f726c642041414421"

# IV GCM (12 bytes)
IV_GCM="000102030405060708090a0b"

# IV CCM (7 to 13 bytes)
IV_CCM_7="00010203040506"
IV_CCM_8="0001020304050607"
IV_CCM_9="000102030405060708"
IV_CCM_10="00010203040506070809"
IV_CCM_11="000102030405060708090a"
IV_CCM_12="000102030405060708090a0b"
IV_CCM_13="000102030405060708090a0b0c"

run_test() {
    local label="$1"
    local algo="$2"
    local key="$3"
    local iv="$4"
    local aad_val="$5"
    local taglen="$6"
    local pt_file="$7"
    local aad_opt=""

    TOTAL=$((TOTAL + 1))

    if [ -n "$aad_val" ]; then
        aad_opt="-aad $aad_val"
    fi

    # encrypt with provider
    if ! $TOOL enc -algo "$algo" -provider "$PROVIDER" \
            -K "$key" -iv "$iv" $aad_opt -taglen "$taglen" \
            -in "$pt_file" -out "$DIR/pv.enc"  2>/dev/null; then
        echo "KO   | $label | pv encrypt failed"
        FAIL=$((FAIL + 1))
        return
    fi

    # decrypt with provider
    if ! $TOOL dec -algo "$algo" -provider "$PROVIDER" \
            -K "$key" $aad_opt \
            -in "$DIR/pv.enc" -out "$DIR/pv.dec"  2>/dev/null; then
        echo "KO   | $label | pv decrypt failed"
        FAIL=$((FAIL + 1))
        return
    fi

    # verify that the decrypted plaintext matches the original plaintext
    if ! diff -q "$pt_file" "$DIR/pv.dec" >/dev/null 2>/dev/null; then
        echo "KO   | $label | plaintext mismatch after round-trip"
        FAIL=$((FAIL + 1))
        return
    fi

    # encrypt software
    if ! $TOOL enc -algo "$algo" -soft \
            -K "$key" -iv "$iv" $aad_opt -taglen "$taglen" \
            -in "$pt_file" -out "$DIR/sw.enc"  2>/dev/null; then
        echo "SKIP | $label | software encrypt failed"
        SKIP=$((SKIP + 1))
        return
    fi

    # decrypt provider | software
    if ! $TOOL dec -algo "$algo" -provider "$PROVIDER" \
            -K "$key" $aad_opt \
            -in "$DIR/sw.enc" -out "$DIR/cross.dec"  2>/dev/null; then
        echo "KO   | $label | interop sw->pv decrypt failed"
        FAIL=$((FAIL + 1))
        return
    fi

    if ! diff -q "$pt_file" "$DIR/cross.dec" >/dev/null 2>/dev/null; then
        echo "KO   | $label | interop sw->pv plaintext mismatch"
        FAIL=$((FAIL + 1))
        return
    fi

    if ! $TOOL dec -algo "$algo" -soft \
            -K "$key" $aad_opt \
            -in "$DIR/pv.enc" -out "$DIR/cross2.dec"  2>/dev/null; then
        echo "KO   | $label | interop pv->sw decrypt failed"
        FAIL=$((FAIL + 1))
        return
    fi

    if ! diff -q "$pt_file" "$DIR/cross2.dec" >/dev/null 2>/dev/null; then
        echo "KO   | $label | interop pv->sw plaintext mismatch"
        FAIL=$((FAIL + 1))
        return
    fi

    # negative test: try to decrypt with wrong key
    if $TOOL dec -algo "$algo" -provider "$PROVIDER" \
            -K "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" $aad_opt \
            -in "$DIR/pv.enc" -out "$DIR/bad.dec"  2>/dev/null; then
        echo "KO   | $label | NEGATIVE: wrong key accepted!"
        FAIL=$((FAIL + 1))
        return
    fi

    echo "OK   | $label"
    PASS=$((PASS + 1))

    rm -f "$DIR"/pv.* "$DIR"/sw.* "$DIR"/cross* "$DIR"/bad.*
}

echo "----  stmaead TOOL TEST - provider: $PROVIDER ----"
echo ""
echo "Generating test files..."

dd if=/dev/urandom of="$DIR/1B.bin"    bs=1     count=1      2>/dev/null
dd if=/dev/urandom of="$DIR/16B.bin"   bs=16    count=1      2>/dev/null
dd if=/dev/urandom of="$DIR/33B.bin"   bs=1     count=33     2>/dev/null
dd if=/dev/urandom of="$DIR/128B.bin"  bs=128   count=1      2>/dev/null
dd if=/dev/urandom of="$DIR/1K.bin"    bs=1K    count=1      2>/dev/null
dd if=/dev/urandom of="$DIR/4K.bin"    bs=1K    count=4      2>/dev/null
dd if=/dev/urandom of="$DIR/32K.bin"   bs=1K    count=32     2>/dev/null
dd if=/dev/urandom of="$DIR/60K.bin"   bs=1K    count=60     2>/dev/null
dd if=/dev/urandom of="$DIR/64K.bin"   bs=1K    count=64     2>/dev/null
dd if=/dev/urandom of="$DIR/100K.bin"  bs=1K    count=100    2>/dev/null
dd if=/dev/urandom of="$DIR/128K.bin"  bs=1K    count=128    2>/dev/null
dd if=/dev/urandom of="$DIR/256K.bin"  bs=1K    count=256    2>/dev/null
dd if=/dev/urandom of="$DIR/512K.bin"  bs=1K    count=512    2>/dev/null
dd if=/dev/urandom of="$DIR/1M.bin"    bs=1K    count=1024   2>/dev/null
dd if=/dev/urandom of="$DIR/2M.bin"    bs=1K    count=2048   2>/dev/null
	
echo ""

# GCM
echo "--------------------------------"
echo "  GCM - AES-128/192/256, IV=12 bytes"
echo "--------------------------------"

for keyname in K128 K192 K256; do
    eval key=\$$keyname
    bits=$(( ${#key} * 4 ))

    echo ""
    echo "--- AES-${bits}-GCM ---"

    for f in 1B 16B 33B 128B 1K 4K 32K 60K 64K 100K 128K 256K 512K 1M 2M; do
        run_test "GCM-${bits} | ${f}" "gcm" "$key" "$IV_GCM" "$AAD" 16 "$DIR/${f}.bin"
    done

    run_test "GCM-${bits} | 4K | no-aad" "gcm" "$key" "$IV_GCM" "" 16 "$DIR/4K.bin"

    run_test "GCM-${bits} | 4K | tag12" "gcm" "$key" "$IV_GCM" "$AAD" 12 "$DIR/4K.bin"
    run_test "GCM-${bits} | 4K | tag8"  "gcm" "$key" "$IV_GCM" "$AAD" 8  "$DIR/4K.bin"
done

echo ""

# CCM - nonce (7 to 13 bytes) 
echo "--------------------------------"
echo "  CCM - AES-256, nonce sizes 7 to 13 bytes"
echo "--------------------------------"

for nonce_len in 7 8 9 10 11 12 13; do
    eval iv=\$IV_CCM_${nonce_len}

    # calculate L and max message size for current nonce length
    L=$((15 - nonce_len))
    if [ $L -ge 4 ]; then
        max_msg="too large"
    elif [ $L -eq 3 ]; then
        max_msg="16MB"
    elif [ $L -eq 2 ]; then
        max_msg="65535B"
    fi

    echo ""
    echo "--- CCM nonce=${nonce_len}B (L=${L}, max=${max_msg}) ---"

    for f in 1B 16B 33B 128B 1K 4K 32K; do
        run_test "CCM-256 nonce=${nonce_len} | ${f}" "ccm" "$K256" "$iv" "$AAD" 16 "$DIR/${f}.bin"
    done

    if [ $nonce_len -le 12 ]; then
        for f in 60K 64K 128K 256K 1M; do
            run_test "CCM-256 nonce=${nonce_len} | ${f}" "ccm" "$K256" "$iv" "$AAD" 16 "$DIR/${f}.bin"
        done
    fi

    if [ $nonce_len -eq 13 ]; then
        run_test "CCM-256 nonce=13 | 60K" "ccm" "$K256" "$iv" "$AAD" 16 "$DIR/60K.bin"
    fi

    run_test "CCM-256 nonce=${nonce_len} | 4K | no-aad" "ccm" "$K256" "$iv" "" 16 "$DIR/4K.bin"

    run_test "CCM-256 nonce=${nonce_len} | 4K | tag12" "ccm" "$K256" "$iv" "$AAD" 12 "$DIR/4K.bin"
    run_test "CCM-256 nonce=${nonce_len} | 4K | tag8"  "ccm" "$K256" "$iv" "$AAD" 8  "$DIR/4K.bin"
done

echo ""


# CCM - nonce=7 bytes
echo "--------------------------------"
echo "  CCM - AES-128/192, nonce=7 bytes"
echo "--------------------------------"

for keyname in K128 K192; do
    eval key=\$$keyname
    bits=$(( ${#key} * 4 ))

    echo ""
    echo "--- AES-${bits}-CCM ---"

    for f in 1B 16B 128B 1K 4K 32K 128K 1M; do
        run_test "CCM-${bits} nonce=7 | ${f}" "ccm" "$key" "$IV_CCM_7" "$AAD" 16 "$DIR/${f}.bin"
    done
done

echo ""

echo "--------------------------------"
echo "  Final results"
echo "--------------------------------"
echo "TOTAL: $TOTAL  |  PASS: $PASS  |  FAIL: $FAIL  |  SKIP: $SKIP"
if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: ALL PASS ✓"
else
    echo "RESULT: FAIL"
fi

rm -rf "$DIR"

if [ -n "${OLD_PRINTK:-}" ] && [ -w /proc/sys/kernel/printk ]; then
    echo "$OLD_PRINTK" > /proc/sys/kernel/printk
fi

exit $FAIL