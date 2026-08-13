# stmaead - Outil CLI AES-GCM/CCM of STM32

Command-line tool to encrypt and decrypt files using AES-GCM or AES-CCM
through the STM32 provider (CRYP hardware acceleration).

Replace `openssl enc` which does not support AEAD modes.

## Compilation

```bash
$CC -o stmaead stmaead.c -lcrypto
```

## Usage

```
stmaead enc -algo gcm|ccm -K <hex> -iv <hex> [-aad <hex>] [-taglen <n>]
            -in <file> -out <file> [-provider <name>] [-soft]

stmaead dec -algo gcm|ccm -K <hex> -in <file> -out <file>
            [-aad <hex>] [-provider <name>] [-soft]
```

### Options

| Option      | Description                                           	|
|-------------|---------------------------------------------------------|
| `-algo`     | `gcm` ou `ccm` (required)                           	|
| `-K`        | AES key in hex (32/48/64 chars -> 128/192/256 auto)    	|
| `-iv`       | Nonce in hex (obligatoire pour enc)                    	|
| `-aad`      | Additional Authenticated Data in hex (optionnel)       	|
| `-taglen`   | Tag size 4-16 bytes (default: 16)                 	|
| `-in`       | Input file	                                    	|
| `-out`      | Output file                                     	|
| `-provider` | `stm32prov` either implementation (AF_ALG or CRYPTODEV) |
| `-soft`     | Use implemntation software instead of hardware          |

### IV Sizes by Mode

| Mode | IV Size   | Hex Fromat          |
|------|-----------|---------------------|
| GCM  | 12 bytes  | 24 hex characters   |
| CCM  | 7 bytes   | 14 hex characters   |
| CCM  | 8 bytes   | 16 hex characters   |
| CCM  | ...       | ...                 |
| CCM  | 13 bytes  | 26 hex characters   |

**CCM** : as the nonce gets longer, the maximum message size gets smaller:

| Nonce | L  | Max message  |
|-------|----|--------------|
| 7B    | 8  | ~too large   |
| 8B    | 7  | ~too large   |
| 11B   | 4  | 4 GB         |
| 12B   | 3  | 16 MB        |
| 13B   | 2  | 65535 bytes  |

## Examples

### GCM - Encrypting and decrypting a file

```bash
export OPENSSL_MODULES=$HOME/path/to/stm32prov.so
KEY=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff5
IV=000102030405060708090a0b

# Create a test file
echo "Message secret" > /tmp/secret.txt

# Encrypt
./stmaead enc -algo gcm -K $KEY -iv $IV \
    -in /tmp/secret.txt -out /tmp/secret.enc

# Decrypt
./stmaead dec -algo gcm -K $KEY \
    -in /tmp/secret.enc -out /tmp/secret.dec

# Verify
diff /tmp/secret.txt /tmp/secret.dec && echo "OK"
```

### GCM - AAD and tag

```bash
KEY=2b7e151628aed2a6abf7158809cf4f3c
IV=000102030405060708090a0b
AAD=48656c6c6f

# Encrypt with AAD + tag 12 bytes
./stmaead enc -algo gcm -K $KEY -iv $IV -aad $AAD -taglen 12 \
    -in /tmp/data.bin -out /tmp/data.enc

# Decrypt
./stmaead dec -algo gcm -K $KEY -aad $AAD \
    -in /tmp/data.enc -out /tmp/data.dec

# Different AAD -> authentication failed
./stmaead dec -algo gcm -K $KEY -aad FF \
    -in /tmp/data.enc -out /tmp/data.bad
# -> AUTHENTICATION FAILED
```

### GCM - Large file (chunking)

```bash
# File of 10 MB
dd if=/dev/urandom of=/tmp/huge.bin bs=1M count=10

# Encrypt - chunks of 60 KB
./stmaead enc -algo gcm -K $KEY -iv $IV \
    -in /tmp/huge.bin -out /tmp/huge.enc
# -> Encrypted: 10485760 bytes -> 171 chunks

# Decrypt
./stmaead dec -algo gcm -K $KEY \
    -in /tmp/huge.enc -out /tmp/huge.dec

diff /tmp/huge.bin /tmp/huge.dec && echo "OK"
```

### CCM - Nonce of 7 bytes

```bash
KEY=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff5
IV_CCM=00010203040506

./stmaead enc -algo ccm -K $KEY -iv $IV_CCM \
    -in /tmp/data.bin -out /tmp/data_ccm.enc

./stmaead dec -algo ccm -K $KEY \
    -in /tmp/data_ccm.enc -out /tmp/data_ccm.dec
```

### Backend selection AF_ALG/Cryptodev

```bash
# AF_ALG
./stmaead enc -algo gcm -provider stm32prov -K $KEY -iv $IV \
    -in file.bin -out file.enc

# Cryptodev
./stmaead enc -algo gcm -provider stm32prov -K $KEY -iv $IV \
    -in file.bin -out file.enc

# Software OpenSSL
./stmaead enc -algo gcm -soft -K $KEY -iv $IV \
    -in file.bin -out file.enc
```

## Encrypted file format

The tool uses a header-based format to store metadata.
Only the key is not stored in the file.

```
┌─── HEADER ──────────────────────────────────┐
│ "SGC1"       magic (4 bytes)                │
│ algo_id      1=GCM, 2=CCM (1 byte)          │
│ chunk_size   60KB (4 bytes)                 │
│ nonce_len    12 for GCM (1 byte)            │
│ nonce        the base nonce (N bytes)       │
│ taglen       16 by default (1 byte)         │
│ aadlen       AAD size (4 bytes)             │
│ aad          AAD data (N bytes)             │
├─── CHUNKS (repeated) ───────────────────────│
│ chunk_len    plaintext size (4 bytes)       │
│ ciphertext   encrypted data                 │
│ tag          authentification tag           │
├─────────────────────────────────────────────│
│ 0x00000000   end marqueur                   │
└─────────────────────────────────────────────┘
```
Each chunk uses an auto-incremented nonce, similar to TLS record processing.

## Test script

### Run the tests

```bash
chmod +x stm32_test_aead.sh
./stm32_test_aead.sh stm32prov   # test with AF_ALG
./stm32_test_aead.sh stm32prov   # test with cryptodev
```

### What is tested : stm32_test_aead.sh

The script tests about 170 combinations :

**GCM** (3 keys × 15 sizes + variants) :
- AES-128/192/256-GCM
- Sizes : 1B, 16B, 33B, 128B, 1K, 4K, 32K, 60K, 64K, 100K, 128K, 256K, 512K, 1M, 2M
- without AAD, with AAD
- Tag 8, 12, 16 bytes

**CCM** (7 nonces × sizes + 2 keys) :
- Nonce sizes from 7 to 13 bytes (all supported values)
- Message sizes adapted to the nonce size
- AES-128/192/256

**Each test checks**:
1. Hardware encryption
2. Hardware decryption (round-trip)
3. Software encryption (reference)
4. Interoperability: software -> hardware decrypt
5. Interoperability: hardware -> software decrypt
6. Negative test: wrong key -> rejected

### Expected result

```
TOTAL: 171  |  PASS: 171  |  FAIL: 0  |  SKIP: 0
RESULT: ALL PASS ✓
```