#!/bin/sh
set -eu

BENCH="./bench_tp.sh"

run_impl() {
  impl="$1"
  $BENCH "$impl" 5  16     ; sleep 1
  $BENCH "$impl" 5  64     ; sleep 1
  $BENCH "$impl" 5  128    ; sleep 1
  $BENCH "$impl" 5  256    ; sleep 1
  $BENCH "$impl" 5  512    ; sleep 1
  $BENCH "$impl" 5  1024   ; sleep 1
  $BENCH "$impl" 5  2048   ; sleep 1
  $BENCH "$impl" 5  4096   ; sleep 1
  $BENCH "$impl" 5  8192   ; sleep 1
  $BENCH "$impl" 5  16384  ; sleep 1
  $BENCH "$impl" 5  32768  ; sleep 1
  $BENCH "$impl" 5  65536  ; sleep 1
  $BENCH "$impl" 5  131072 ; sleep 1
  $BENCH "$impl" 10 262144 ; sleep 1
  $BENCH "$impl" 15 524288 ; sleep 1
  $BENCH "$impl" 20 1048576
}

echo ""
echo "============================================================"
echo " STM32 OpenSSL provider via AF_ALG"
echo "============================================================"
echo ""
run_impl st_afalg

echo ""
sleep 5

echo ""
echo "============================================================"
echo "  STM32 OpenSSL provider via Cryptodev"
echo "============================================================"
echo ""
run_impl st_cryptodev

echo ""
echo "============================================================"
echo "  out : bench.json"
echo "============================================================"