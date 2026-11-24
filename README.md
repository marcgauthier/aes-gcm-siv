<p align="center">
  <img src="icon.png" width="256" alt="AES-GCM-SIV logo" />
</p>

<details align="center">
<summary><sub>Icon credit</sub></summary>
<p><sub>The logo adapts the Go gopher designed by Renée French, licensed under <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>. See <a href="https://go.dev/blog/gopher">The Go Gopher</a>.</sub></p>
</details>

---

# aes-gcm-siv

aes-gcm-siv is a pure Go port of the AES-GCM-SIV implementation in AWS-LC.
It provides AES-128-GCM-SIV and AES-256-GCM-SIV, both with nonce misuse
resistance, through Go's `cipher.AEAD` interface. [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452.html)

## Quick start

Requires Go 1.21 or later and hardware AES enabled on amd64 or Linux arm64.
On amd64 that means AES-NI, SSSE3, and SSE4.1. On arm64 it means the AES
instruction extension. `New` returns an error if Go's native hardware
backend is unavailable, including under `purego` or the BoringCrypto
experiment.

```sh
go get github.com/marcgauthier/aes-gcm-siv
```

```go
package main

import (
	"crypto/rand"
	"fmt"
	"log"

	gcmsiv "github.com/marcgauthier/aes-gcm-siv"
)

func main() {
	key := make([]byte, gcmsiv.KeySize256) // Use KeySize128 for AES-128-GCM-SIV.
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	aead, err := gcmsiv.New(key)
	if err != nil {
		log.Fatal(err)
	}

	nonceSize := aead.NonceSize()
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatal(err)
	}

	// Store the nonce before the ciphertext and its authentication tag.
	aad := []byte("example context")
	sealed := aead.Seal(nonce, nonce, []byte("hello"), aad)

	if len(sealed) < nonceSize+aead.Overhead() {
		log.Fatal("truncated message")
	}
	const maxPlaintext = 1 << 20 // This protocol limits plaintexts to 1 MiB.
	if len(sealed) > nonceSize+maxPlaintext+aead.Overhead() {
		log.Fatal("message too large")
	}
	plaintext, err := aead.Open(nil, sealed[:nonceSize], sealed[nonceSize:], aad)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(plaintext)) // hello
}
```

Generate a fresh random nonce for each encryption. Under the same key and
nonce, repeating the same plaintext and additional authenticated data (AAD)
produces identical ciphertext. [RFC 8452, Section 9](https://www.rfc-editor.org/rfc/rfc8452.html#section-9)

`Seal` appends ciphertext and a 16-byte tag to `dst`. The example passes the
12-byte nonce as `dst` so it can be stored with the ciphertext. `Open` needs the
same nonce and AAD and returns an error with no plaintext if authentication
fails. Both methods panic if the nonce has the wrong length or the output
would overwrite the nonce or AAD. For in-place operation, pass
`plaintext[:0]` to `Seal` or `ciphertext[:0]` to `Open`. Other partial
overlaps with the input panic.

The package enforces RFC 8452's limits of 64 GiB each for plaintext and AAD.
The maximum ciphertext length is 64 GiB plus the 16-byte tag. For untrusted
records, enforce a much smaller protocol-specific limit before buffering or
calling `Open`, which decrypts the full body before checking its tag.
[RFC 8452, Sections 5–6](https://www.rfc-editor.org/rfc/rfc8452.html#section-5)

## Status

The tests cover both key sizes and exercise the table-free POLYVAL
implementation through the public API.

- 179 AWS-LC vectors cover RFC 8452 Appendix C, the Section 8 worked example,
  counter wrapping, and reference-code vectors. Each case checks `Seal`,
  `Open`, and rejection of a modified tag.
- 155 Wycheproof cases include constructed counter-overflow vectors.
- Intermediate-value checks cover record keys, POLYVAL, and field doubling.
  Randomized inputs are also checked against an independent POLYVAL
  implementation based on the RFC 8452 Appendix A relation to GHASH.
- The suite covers round trips across plaintext and AAD lengths, tampering,
  RFC size boundaries, and in-place and invalid buffer overlaps.

```sh
go test -race ./...
go vet ./...
go test -tags=purego ./...
```

## Features

- `New` returns a `cipher.AEAD` for a 16-byte or 32-byte key. An instance can
  be shared by concurrent callers.
- AES uses the Go standard library's hardware backend. The package uses
  `golang.org/x/sys` to check CPU features and ships no assembly of its own.
- POLYVAL uses table-free dot products for all input sizes.

## Performance

The table shows median AES-256-GCM-SIV results from three runs on an Intel
i5-6500 with Go 1.27.3 on linux/amd64. The 1 MiB case includes 12 bytes of
AAD. The other cases use empty AAD. All cases use `nil` destinations.

| Plaintext | Seal MB/s | Seal µs | Open MB/s | Open µs | Allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| 16 B | 24.12 | 0.66 | 23.67 | 0.68 | 3 |
| 64 B | 69.55 | 0.92 | 65.75 | 0.97 | 3 |
| 512 B | 137.48 | 3.72 | 136.28 | 3.76 | 3 |
| 4 KiB | 155.89 | 26.27 | 154.43 | 26.52 | 3 |
| 16 KiB | 155.86 | 105.12 | 157.19 | 104.23 | 3 |
| 64 KiB | 162.16 | 404.13 | 130.30 | 502.95 | 3 |
| 1 MiB | 164.83 | 6361.73 | 124.84 | 8399.15 | 3 |

The three allocations are for the output, the record-key schedule, and a
scratch pad. POLYVAL allocates nothing on the heap.

Run the included `Seal` and `Open` benchmarks.

```sh
go test -run '^$' -bench '^(BenchmarkSeal|BenchmarkOpen)' -benchmem -cpu 1 -benchtime=200ms -count=3
```

## Relation to AWS-LC

The port follows the portable C implementation in `e_aesgcmsiv.c`. It
derives record keys from the nonce and a little-endian counter, then uses
POLYVAL to authenticate AAD, plaintext, and their bit lengths. It mixes
the nonce into the tag and uses a wrapping little-endian 32-bit counter
for encryption. [AWS-LC](https://github.com/aws/aws-lc)

- The AEAD implementation covers key derivation, tag computation, and
  counter-mode encryption. [gcmsiv.go](gcmsiv.go)
- The POLYVAL implementation contains the field arithmetic and direct dot
  products. [polyval.go](polyval.go)
- The test suite uses vectors from AWS-LC and Wycheproof. The repository
  also includes benchmarks for the AEAD and POLYVAL.
  [gcmsiv_test.go](gcmsiv_test.go), [polyval_bench_test.go](polyval_bench_test.go), [testdata](testdata/)

## License

Copyright 2026 marcgauthier.

Licensed under the Apache License, Version 2.0. [LICENSE](LICENSE)

The third-party license file documents the AWS-LC sources and test vector
attribution. [THIRD-PARTY-LICENSE.md](THIRD-PARTY-LICENSE.md)
