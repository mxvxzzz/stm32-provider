#!/bin/sh
set -e
# source /opt/st/stm32mp2/5.0.15-openstlinux-6.6-yocto-scarthgap-mpu-v26.02.18/environment-setup
make clean BACKEND=afalg && make clean BACKEND=cryptodev
rm -f pv_afalg.so && rm -f pv_cryptodev.so
echo "rm -f pv_afalg.so && rm -f pv_cryptodev.so"
echo "clean both"
make BUILD=dev BACKEND=afalg
mv stm32prov.so pv_afalg.so
echo "OK : mv stm32prov.so pv_afalg.so"
make clean BACKEND=afalg
echo "clean afalg"
make BUILD=dev BACKEND=cryptodev
mv stm32prov.so pv_cryptodev.so
echo "OK : mv stm32prov.so pv_cryptodev.so"
ssh root@IP_board <<'EOF'
rm -f pv_cipher/pv_afalg.so pv_cipher/pv_cryptodev.so
ls -l pv_cipher/
EOF
scp pv_afalg.so pv_cryptodev.so root@IP_board:/home/root/pv_cipher/
make clean BACKEND=cryptodev
echo "clean cryptodev"