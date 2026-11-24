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

Requires Go 1.21 or later on a 64-bit target.

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
fails. Both methods panic if the nonce has the wrong length.

Keep plaintext and AAD at or below 64 GiB each for RFC 8452 interoperability.
`Seal` panics on plaintext above that limit. The package's size checks allow
AAD up to `2^61 - 1` bytes and let `Open` attempt authentication on ciphertexts
up to 16 bytes beyond the RFC limit. [RFC 8452, Section 6](https://www.rfc-editor.org/rfc/rfc8452.html#section-6)

## Status

The tests cover both key sizes. The vector and round-trip tests exercise
both POLYVAL paths independently.

- 179 AWS-LC vectors cover RFC 8452 Appendix C, the Section 8 worked example,
  counter wrapping, and reference-code vectors. Each case checks `Seal`,
  `Open`, and rejection of a modified tag.
- 155 Wycheproof cases include constructed counter-overflow vectors.
- Intermediate-value checks cover record keys, POLYVAL, and field doubling.
  Randomized inputs are also checked against an independent POLYVAL
  implementation based on the RFC 8452 Appendix A relation to GHASH.
- Round-trip tests vary plaintext and AAD lengths. The suite also covers
  tampering and in-place operation.

```sh
go test -race ./...
go vet ./...
```

## Features

- `New` returns a `cipher.AEAD` for a 16-byte or 32-byte key. An instance can
  be shared by concurrent callers.
- The package uses only the Go standard library, with no cgo or
  package-specific assembly. AES comes from `crypto/aes`, which uses
  hardware acceleration on supported platforms.
- POLYVAL uses direct, table-free dot products for short inputs and
  precomputed multiplication tables with data-dependent lookups for longer
  inputs.

## Performance

The table shows the best of repeated AES-256-GCM-SIV runs on an Intel i5-6500
with Go 1.27 on linux/amd64. The 1 MiB case includes 12 bytes of AAD. The
other cases use empty AAD. All cases use `nil` destinations.

| Plaintext | Seal MB/s | Seal µs | Open MB/s | Open µs | Allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| 16 B | 18.5 | 0.87 | 13.0 | 1.23 | 3 |
| 64 B | 58.5 | 1.09 | 45.1 | 1.42 | 3 |
| 4 KiB | 306 | 13.4 | 266 | 15.4 | 3 |
| 16 KiB | 328 | 50.0 | 279 | 58.7 | 3 |
| 64 KiB | 347 | 189 | 265 | 247 | 3 |
| 1 MiB | 297 | 3527 | 279 | 3754 | 3 |

The AES record-key schedule dominates small-message latency. The three
allocations are for the output, the record-key schedule, and a scratch pad.
POLYVAL allocates nothing on the heap.

Run the included `Seal` and `Open` benchmarks.

```sh
go test -run '^$' -bench '^(BenchmarkSeal|BenchmarkOpen)' -benchmem
```

### Comparison with other Go packages

Each package encrypted the same plaintexts on the same machine. The table
shows each package's best `Seal` throughput in MB/s across repeated runs.
Tink uses its NoPrefix template and the measurement includes `crypto/rand`
for nonce generation. Eric Lagergren's package uses PCLMUL assembly for
POLYVAL.

| Plaintext | aes-gcm-siv | ericlagergren | tink | cryptonite | fernandezvara |
| --- | ---: | ---: | ---: | ---: | ---: |
| 16 B | 18.5 | 29.9 | 8.4 | 6.2 | 1.4 |
| 64 B | 58.5 | 101 | 30.5 | 28.7 | 2.4 |
| 512 B | 181 | 332 | 97.3 | 53.5 | 3.0 |
| 4 KiB | 306 | 468 | 126 | 59.2 | 2.7 |
| 16 KiB | 328 | 513 | 127 | 56.9 | 3.0 |
| 64 KiB | 347 | 486 | 135 | 56.8 | 2.9 |
| Allocs/op (16 B / 64 KiB) | 3 / 3 | 1 / 1 | 11 / 11 | 11 / 11 | 12 / 12 |

## Relation to AWS-LC

The port follows the portable C implementation in `e_aesgcmsiv.c`. It
derives record keys from the nonce and a little-endian counter, then uses
POLYVAL to authenticate AAD, plaintext, and their bit lengths. It mixes
the nonce into the tag and uses a wrapping little-endian 32-bit counter
for encryption. [AWS-LC](https://github.com/aws/aws-lc)

- The AEAD implementation covers key derivation, tag computation, and
  counter-mode encryption. [gcmsiv.go](gcmsiv.go)
- The POLYVAL implementation contains the field arithmetic, direct dot
  products, and multiplication tables. [polyval.go](polyval.go)
- The test suite uses vectors from AWS-LC and Wycheproof. The repository
  also includes benchmarks for the AEAD and POLYVAL.
  [gcmsiv_test.go](gcmsiv_test.go), [polyval_bench_test.go](polyval_bench_test.go), [testdata](testdata/)

## License

Copyright 2026 marcgauthier.

Licensed under the Apache License, Version 2.0. [LICENSE](LICENSE)

The third-party license file documents the AWS-LC sources and test vector
attribution. [THIRD-PARTY-LICENSE.md](THIRD-PARTY-LICENSE.md)
