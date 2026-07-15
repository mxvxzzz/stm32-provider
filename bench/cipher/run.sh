#!/bin/sh
set -eu

BENCH="./bench.sh"

run_impl() {
  impl="$1"

  $BENCH "$impl" 3 16
  $BENCH "$impl" 3 17
  $BENCH "$impl" 3 31
  $BENCH "$impl" 3 33
  $BENCH "$impl" 3 47
  $BENCH "$impl" 3 63
  $BENCH "$impl" 3 64
  $BENCH "$impl" 3 63
  $BENCH "$impl" 3 128
  $BENCH "$impl" 3 256
  $BENCH "$impl" 3 512
  $BENCH "$impl" 3 1024
  $BENCH "$impl" 3 2048
  $BENCH "$impl" 3 4095
  $BENCH "$impl" 3 4096
  $BENCH "$impl" 3 4097
  $BENCH "$impl" 3 8191
  $BENCH "$impl" 3 8192
  $BENCH "$impl" 3 8193
  $BENCH "$impl" 3 16383
  $BENCH "$impl" 3 16384
  $BENCH "$impl" 3 16385
  $BENCH "$impl" 3 32768
  $BENCH "$impl" 5 65535
  $BENCH "$impl" 5 65536
  $BENCH "$impl" 5 65537
  $BENCH "$impl" 5 131071
  $BENCH "$impl" 5 131072
  $BENCH "$impl" 5 131073
  $BENCH "$impl" 5 262143
  $BENCH "$impl" 5 262144
  $BENCH "$impl" 5 262145
  $BENCH "$impl" 5 524287
  $BENCH "$impl" 5 524288
  $BENCH "$impl" 5 524289
  $BENCH "$impl" 5 1048575
  $BENCH "$impl" 5 1048576
  $BENCH "$impl" 5 1048577
}

echo ""
echo "============================================================"
echo " OpenSSL software provider"
echo "============================================================"
echo ""
run_impl soft

echo ""
sleep 5

echo ""
echo "============================================================"
echo " STM32 provider via AFALG"
echo "============================================================"
echo ""
run_impl pv_afalg

echo ""
sleep 5

echo ""
echo "============================================================"
echo " STM32 provider via Cryptodev"
echo "============================================================"
echo ""
run_impl pv_cryptodev

echo ""
sleep 5

echo ""
echo "============================================================"
echo " STM32 engine via AFALG"
echo "============================================================"
echo ""
run_impl eng_afalg

echo ""
sleep 5

echo ""
echo "============================================================"
echo " STM32 engine via Devcrypto"
echo "============================================================"
echo ""
run_impl eng_cryptodev

echo ""
echo "============================================================"
echo " out : bench.json"
echo "============================================================"