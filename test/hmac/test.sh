#!/bin/bash

set -u

DATA_FILE="donnees.bin"

KEY_HEX=$(openssl rand -hex 32)

algs=(
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

if [ ! -f "$DATA_FILE" ]; then
    echo "Error: file $DATA_FILE not found"
    exit 1
fi

echo "Key generated"
echo

for algo in "${algs[@]}"; do
    display_algo="HMAC-$algo"

    ref=$(openssl mac -digest "$algo" \
        -macopt "hexkey:$KEY_HEX" \
        -in "$DATA_FILE" HMAC 2>/dev/null)
    ref_status=$?

    if [ $ref_status -ne 0 ]; then
        echo "$display_algo -> Error: software reference failed"
        continue
    fi

    provider=$(openssl mac -digest "$algo" \
        -macopt "hexkey:$KEY_HEX" \
        -in "$DATA_FILE" \
        -provider stm32prov -propquery "provider=stm32" HMAC 2>/dev/null)
    provider_status=$?

    if [ $provider_status -ne 0 ]; then
        echo "$display_algo -> Error: provider failed"
        continue
    fi

    if [ "$provider" = "$ref" ]; then
        echo "$display_algo -> Ok"
    else
        echo "$display_algo -> Error: provider output differs from reference"
        echo "  software : $ref"
        echo "  provider : $provider"
    fi
done