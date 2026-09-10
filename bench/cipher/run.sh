#!/bin/sh
set -eu

BENCH="./evp_bench.sh"

run_impl_full() {
  impl="$1"

  $BENCH "$impl" 5 16
  $BENCH "$impl" 5 23
  $BENCH "$impl" 5 39
  $BENCH "$impl" 5 64
  $BENCH "$impl" 5 128
  $BENCH "$impl" 5 256
  $BENCH "$impl" 5 512
  $BENCH "$impl" 5 1024
  $BENCH "$impl" 5 2048
  $BENCH "$impl" 5 4096
  $BENCH "$impl" 5 8192
  $BENCH "$impl" 5 16384
  $BENCH "$impl" 5 32768
  $BENCH "$impl" 5 65536
  $BENCH "$impl" 5 95535
  $BENCH "$impl" 5 131072
  $BENCH "$impl" 5 200704
  $BENCH "$impl" 5 262144
  $BENCH "$impl" 5 422144
  $BENCH "$impl" 5 524288
  $BENCH "$impl" 5 742144
  $BENCH "$impl" 5 902144
  $BENCH "$impl" 5 1000000
}

run_impl_short() {
  impl="$1"

  $BENCH "$impl" 5 16
  $BENCH "$impl" 5 23
  $BENCH "$impl" 5 39
  $BENCH "$impl" 5 64
  $BENCH "$impl" 5 128
  $BENCH "$impl" 5 256
  $BENCH "$impl" 5 512
  $BENCH "$impl" 5 1024
  $BENCH "$impl" 5 2048
  $BENCH "$impl" 5 4096
  $BENCH "$impl" 5 8192
  $BENCH "$impl" 5 16384
  $BENCH "$impl" 5 32768
  $BENCH "$impl" 5 65536
  $BENCH "$impl" 5 95535
  $BENCH "$impl" 5 131072
  $BENCH "$impl" 5 200704
}

echo ""
echo "============================================================"
echo " STM32 provider via AFALG"
echo "============================================================"
echo ""
run_impl_full pv_afalg

echo ""
sleep 5

echo ""
echo "============================================================"
echo " STM32 provider via Cryptodev"
echo "============================================================"
echo ""
run_impl_full pv_cryptodev

echo ""
sleep 5

echo ""
echo "============================================================"
echo " STM32 engine via Devcrypto"
echo "============================================================"
echo ""
run_impl_full eng_cryptodev

echo ""
sleep 5

echo ""
echo "============================================================"
echo " OpenSSL software provider"
echo "============================================================"
echo ""
run_impl_full soft

echo ""
sleep 5

echo ""
echo "============================================================"
echo " STM32 engine via AFALG"
echo "============================================================"
echo ""
run_impl_short eng_afalg

echo ""
echo "============================================================"
echo " out : bench.json"
echo "============================================================"