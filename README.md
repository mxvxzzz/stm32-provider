# STM32MPU Provider

Experimental OpenSSL 3 provider implementing digest algorithms through the Linux AF_ALG interface. In OpenSSL terms, a provider is a unit of code that offers implementations for operations such as digests, ciphers, signatures, and more.

This project uses:
- A custom OpenSSL provider module: `stm32_provider.so`
- Implementations through `AF_ALG`
- `libprov` for provider error helpers
- `bear` to generate `compile_commands.json` for editor integration

---

## Goals

This project aims to:

- understand OpenSSL 3 provider internals
- implement each operation supported by the provider
- connect OpenSSL digest dispatch with Linux kernel crypto through AF_ALG and cryptodev
- prepare a framework for benchmarking different crypto paths: AF_ALG, cryptodev, legacy engines, and software implementations

---

## Supported digests

Currently implemented:

- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA3-256
- SHA3-384
- SHA3-512

---

## Architecture

The project is split into clear layers:

- `prov.c`  
  provider entry point and provider dispatch table

- `digest/digest.c`  
  OpenSSL-facing digest layer (`newctx`, `init`, `update`, `final`, provider digest dispatch)

- `digest/hash_afalg.c`  
  AF_ALG-facing layer (`socket`, `bind`, `accept`, `write`, `read`)

- `include/err.h` + `err.c`  
  provider-specific error handling and reason strings

- `libprov/`  
  helper library used for provider-side error reporting

---

## Architecture diagram

```mermaid
flowchart TD
    A[OpenSSL Core] --> B[stm32_provider.so]
    B --> C[prov.c]
    C --> D[digest/digest.c]
    D --> E[digest/hash_afalg.c]
    E --> F[Interface Linux AF_ALG]
    C --> G[err.c / include/err.h]
    C --> H[libprov]

```

## How to load the provider

OpenSSL command-line tools accept provider options such as -provider and -provider-path, and openssl list can display loaded providers, provider versions, and available algorithms.

- List loaded providers

  `openssl list -providers`
- Load this provider from the current directory

  `openssl list -provider-path . -provider stm32_provider -providers`
- List digest algorithms exposed by this provider

  `openssl list -provider-path . -provider stm32_provider -digest-algorithms`
- Verbose provider information

  `openssl list -provider-path . -provider stm32_provider -providers -verbose`