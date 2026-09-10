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
        # Reference software
        ref=$(openssl dgst -"$algo" "$file" 2>/dev/null)
        ref_status=$?

        # Provider
        provider=$(openssl dgst -"$algo" \
            -provider stm32prov -propquery "provider=stm32" \
            "$file" 2>/dev/null)
        provider_status=$?

        if [ $ref_status -ne 0 ]; then
            echo "  $algo -> Error: software reference failed"
            continue
        fi

        if [ $provider_status -ne 0 ]; then
            echo "  $algo -> Error: provider failed"
            continue
        fi

        if [ "$provider" = "$ref" ]; then
            echo "  $algo -> Ok"
        else
            echo "  $algo -> Error: output differs"
            echo "    software : $ref"
            echo "    provider : $provider"
        fi
    done

    echo
done