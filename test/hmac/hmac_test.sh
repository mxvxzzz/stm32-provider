#!/bin/bash

set -u

# --- Configuration ---
FILES=(
    "/tmp/test_16.bin"
    "/tmp/test_64.bin"
    "/tmp/test_128.bin"
    "/tmp/test_256.bin"
    "/tmp/test_4096.bin"
    "/tmp/test_5000.bin"
    "/tmp/test_9000.bin"
    "/tmp/test_64K.bin"
    "/tmp/test_128K.bin"
    "/tmp/test_512K.bin"
    "/tmp/test_1M.bin"
    "/tmp/test_10M.bin"
)

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

# --- Generate key once ---
KEY_HEX=$(openssl rand -hex 32)

echo "Key generated."
echo

# --- Check files exist ---
for f in "${FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "Error: file not found: $f"
        exit 1
    fi
done

# --- Main loop ---
for file in "${FILES[@]}"; do
    size_bytes=$(stat -c %s "$file")
    echo "=== File: $file (${size_bytes} bytes) ==="

    for algo in "${algs[@]}"; do
        display_algo="HMAC-$algo"

        # Reference software
        ref=$(openssl mac -digest "$algo" \
            -macopt "hexkey:$KEY_HEX" \
            -in "$file" HMAC 2>/dev/null)
        ref_status=$?

        # Provider
        provider=$(openssl mac -digest "$algo" \
            -macopt "hexkey:$KEY_HEX" \
            -in "$file" \
            -provider stm32prov -propquery "provider=stm32" HMAC 2>/dev/null)
        provider_status=$?

        if [ $ref_status -ne 0 ]; then
            echo "  $display_algo -> Error: software reference failed"
            continue
        fi

        if [ $provider_status -ne 0 ]; then
            echo "  $display_algo -> Error: provider failed"
            continue
        fi

        if [ "$provider" = "$ref" ]; then
            echo "  $display_algo -> Ok"
        else
            echo "  $display_algo -> Error: output differs"
            echo "    software : $ref"
            echo "    provider : $provider"
        fi
    done

    echo
done

echo "=== Negative tests ==="
echo

NEGATIVE_CASES=(
    "/tmp/test_16.bin SHA256"
    "/tmp/test_4096.bin SHA256"
    "/tmp/test_128K.bin SHA512"
    "/tmp/test_1M.bin SHA3-256"
)

BAD_KEY_HEX=$(openssl rand -hex 32)

for case in "${NEGATIVE_CASES[@]}"; do
    file=$(echo "$case" | awk '{print $1}')
    algo=$(echo "$case" | awk '{print $2}')
    display_algo="HMAC-$algo"

    if [ ! -f "$file" ]; then
        echo "  Error: file not found: $file"
        continue
    fi

    good_hmac=$(openssl mac -digest "$algo" \
        -macopt "hexkey:$KEY_HEX" \
        -in "$file" \
        -provider stm32prov -propquery "provider=stm32" HMAC 2>/dev/null)
    good_status=$?

    bad_hmac=$(openssl mac -digest "$algo" \
        -macopt "hexkey:$BAD_KEY_HEX" \
        -in "$file" \
        -provider stm32prov -propquery "provider=stm32" HMAC 2>/dev/null)
    bad_status=$?

    echo "=== Negative test: $file / $display_algo ==="

    if [ $good_status -ne 0 ]; then
        echo "  Error: unable to compute reference HMAC"
        continue
    fi

    if [ $bad_status -ne 0 ]; then
        echo "  Error: unable to compute reference HMAC"
        continue
    fi

    if [ "$good_hmac" != "$bad_hmac" ]; then
        echo "  Ok: HMAC changes"
    else
        echo "  Error: HMAC is identical with an invalid key"
    fi
done