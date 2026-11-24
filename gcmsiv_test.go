// Copyright 2026 marcgauthier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcmsiv

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// BoringSSL-format vector files (testdata/rfc8452_*.txt, verbatim from AWS-LC)
// ---------------------------------------------------------------------------

type rfcVector struct {
	key, nonce, in, ad, ct, tag []byte
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	// The RFC Section 8 worked example uses quoted ASCII strings.
	if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		return []byte(s[1 : len(s)-1])
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func parseRFCVectors(t *testing.T, path string) []rfcVector {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vecs []rfcVector
	for _, rec := range strings.Split(string(data), "\n\n") {
		m := map[string]string{}
		for _, line := range strings.Split(rec, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				t.Fatalf("%s: bad line %q", path, line)
			}
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
		if len(m) == 0 {
			continue
		}
		for _, k := range []string{"KEY", "NONCE", "IN", "AD", "CT", "TAG"} {
			if _, ok := m[k]; !ok {
				t.Fatalf("%s: record missing %s: %v", path, k, m)
			}
		}
		vecs = append(vecs, rfcVector{
			key:   mustHex(t, m["KEY"]),
			nonce: mustHex(t, m["NONCE"]),
			in:    mustHex(t, m["IN"]),
			ad:    mustHex(t, m["AD"]),
			ct:    mustHex(t, m["CT"]),
			tag:   mustHex(t, m["TAG"]),
		})
	}
	if len(vecs) == 0 {
		t.Fatalf("%s: no vectors parsed", path)
	}
	return vecs
}

func TestRFC8452Vectors(t *testing.T) {
	requireHardwareAES(t)
	files := []string{"testdata/rfc8452_aes128.txt", "testdata/rfc8452_aes256.txt"}
	for _, f := range files {
		for i, v := range parseRFCVectors(t, f) {
			aead, err := New(v.key)
			if err != nil {
				t.Fatalf("%s#%d: %v", f, i, err)
			}
			sealed := aead.Seal(nil, v.nonce, v.in, v.ad)
			want := append(append([]byte{}, v.ct...), v.tag...)
			if !bytes.Equal(sealed, want) {
				t.Fatalf("%s#%d: Seal mismatch\ngot  %x\nwant %x", f, i, sealed, want)
			}
			opened, err := aead.Open(nil, v.nonce, sealed, v.ad)
			if err != nil {
				t.Fatalf("%s#%d: Open failed: %v", f, i, err)
			}
			if !bytes.Equal(opened, v.in) {
				t.Fatalf("%s#%d: Open mismatch\ngot  %x\nwant %x", f, i, opened, v.in)
			}
			// Flipping any tag bit must fail authentication.
			bad := append([]byte{}, sealed...)
			bad[len(bad)-1] ^= 1
			if _, err := aead.Open(nil, v.nonce, bad, v.ad); err == nil {
				t.Fatalf("%s#%d: Open accepted forged tag", f, i)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Wycheproof vectors (testdata/wycheproof_aes_gcm_siv.json)
// ---------------------------------------------------------------------------

type wycheproofFile struct {
	TestGroups []struct {
		KeySize int `json:"keySize"`
		IvSize  int `json:"ivSize"`
		TagSize int `json:"tagSize"`
		Tests   []struct {
			TcID   int      `json:"tcId"`
			Key    string   `json:"key"`
			Iv     string   `json:"iv"`
			Aad    string   `json:"aad"`
			Msg    string   `json:"msg"`
			Ct     string   `json:"ct"`
			Tag    string   `json:"tag"`
			Result string   `json:"result"`
			Flags  []string `json:"flags"`
		} `json:"tests"`
	} `json:"testGroups"`
}

func TestWycheproof(t *testing.T) {
	requireHardwareAES(t)
	data, err := os.ReadFile("testdata/wycheproof_aes_gcm_siv.json")
	if err != nil {
		t.Fatal(err)
	}
	var wf wycheproofFile
	if err := json.Unmarshal(data, &wf); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, g := range wf.TestGroups {
		if g.IvSize != 96 || g.TagSize != 128 || (g.KeySize != 128 && g.KeySize != 256) {
			t.Fatalf("unexpected group sizes %+v", g)
		}
		for _, tc := range g.Tests {
			n++
			key := mustHex(t, tc.Key)
			iv := mustHex(t, tc.Iv)
			aad := mustHex(t, tc.Aad)
			msg := mustHex(t, tc.Msg)
			ct := mustHex(t, tc.Ct)
			tag := mustHex(t, tc.Tag)
			aead, err := New(key)
			if err != nil {
				t.Fatalf("tcId %d: %v", tc.TcID, err)
			}
			ctAndTag := append(append([]byte{}, ct...), tag...)
			switch tc.Result {
			case "valid":
				sealed := aead.Seal(nil, iv, msg, aad)
				if !bytes.Equal(sealed, ctAndTag) {
					t.Fatalf("tcId %d: Seal mismatch\ngot  %x\nwant %x", tc.TcID, sealed, ctAndTag)
				}
				opened, err := aead.Open(nil, iv, ctAndTag, aad)
				if err != nil {
					t.Fatalf("tcId %d: Open failed: %v", tc.TcID, err)
				}
				if !bytes.Equal(opened, msg) {
					t.Fatalf("tcId %d: Open mismatch", tc.TcID)
				}
			case "invalid":
				if _, err := aead.Open(nil, iv, ctAndTag, aad); err == nil {
					t.Fatalf("tcId %d: Open accepted invalid vector (flags %v)", tc.TcID, tc.Flags)
				}
			default:
				t.Fatalf("tcId %d: unknown result %q", tc.TcID, tc.Result)
			}
		}
	}
	if n == 0 {
		t.Fatal("no Wycheproof tests ran")
	}
	t.Logf("%d Wycheproof cases", n)
}

// ---------------------------------------------------------------------------
// Round-trip, tamper and API tests
// ---------------------------------------------------------------------------

func TestRoundTrip(t *testing.T) {
	requireHardwareAES(t)
	rng := rand.New(rand.NewSource(0xC0FFEE))
	ptLens := []int{0, 1, 2, 7, 8, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 100, 255, 256, 1000, 1024, 4096, 16384, 65536}
	adLens := []int{0, 1, 5, 16, 17, 100, 1000}
	for _, keyLen := range []int{16, 32} {
		key := make([]byte, keyLen)
		rng.Read(key)
		aead, err := New(key)
		if err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, NonceSize)
		rng.Read(nonce)
		for _, ptLen := range ptLens {
			pt := make([]byte, ptLen)
			rng.Read(pt)
			for _, adLen := range adLens {
				ad := make([]byte, adLen)
				rng.Read(ad)
				sealed := aead.Seal(nil, nonce, pt, ad)
				if len(sealed) != ptLen+TagSize {
					t.Fatalf("key=%d pt=%d ad=%d: sealed len %d", keyLen, ptLen, adLen, len(sealed))
				}
				opened, err := aead.Open(nil, nonce, sealed, ad)
				if err != nil {
					t.Fatalf("key=%d pt=%d ad=%d: %v", keyLen, ptLen, adLen, err)
				}
				if !bytes.Equal(opened, pt) {
					t.Fatalf("key=%d pt=%d ad=%d: mismatch", keyLen, ptLen, adLen)
				}
			}
		}
	}
}

func TestTamper(t *testing.T) {
	requireHardwareAES(t)
	key := bytes.Repeat([]byte{0x42}, 32)
	aead, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x11}, NonceSize)
	pt := bytes.Repeat([]byte{0xAB}, 100)
	ad := bytes.Repeat([]byte{0xCD}, 64)
	sealed := aead.Seal(nil, nonce, pt, ad)
	// Flip each byte of the sealed output.
	for i := range sealed {
		bad := append([]byte{}, sealed...)
		bad[i] ^= 1
		if _, err := aead.Open(nil, nonce, bad, ad); err == nil {
			t.Fatalf("byte %d flip accepted", i)
		}
	}
	// Flip each byte of AD and nonce.
	for i := range ad {
		bad := append([]byte{}, ad...)
		bad[i] ^= 1
		if _, err := aead.Open(nil, nonce, sealed, bad); err == nil {
			t.Fatalf("ad byte %d flip accepted", i)
		}
	}
	for i := range nonce {
		bad := append([]byte{}, nonce...)
		bad[i] ^= 1
		if _, err := aead.Open(nil, bad, sealed, ad); err == nil {
			t.Fatalf("nonce byte %d flip accepted", i)
		}
	}
	// Truncation and extension.
	if _, err := aead.Open(nil, nonce, sealed[:len(sealed)-1], ad); err == nil {
		t.Fatal("truncated ciphertext accepted")
	}
	if _, err := aead.Open(nil, nonce, append(sealed, 0), ad); err == nil {
		t.Fatal("extended ciphertext accepted")
	}
	if _, err := aead.Open(nil, nonce, sealed[:TagSize-1], ad); err == nil {
		t.Fatal("short ciphertext accepted")
	}
}

func TestAPI(t *testing.T) {
	for _, n := range []int{0, 1, 15, 17, 24, 31, 33, 64} {
		if _, err := New(make([]byte, n)); err == nil {
			t.Fatalf("New(%d bytes) accepted", n)
		}
	}
	requireHardwareAES(t)
	aead, err := New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if aead.NonceSize() != NonceSize || aead.Overhead() != TagSize {
		t.Fatal("bad sizes")
	}
	mustPanic(t, func() { aead.Seal(nil, make([]byte, 11), nil, nil) })
	mustPanic(t, func() { aead.Seal(nil, make([]byte, 13), nil, nil) })
	mustPanic(t, func() { aead.Open(nil, make([]byte, 0), make([]byte, 16), nil) })

	// dst is appended to, not overwritten.
	dst := []byte("prefix:")
	out := aead.Seal(dst, make([]byte, 12), []byte("hi"), nil)
	if string(out[:len(dst)]) != "prefix:" || len(out) != len(dst)+2+TagSize {
		t.Fatalf("Seal append broken: %x", out)
	}
	back, err := aead.Open(dst, make([]byte, 12), out[len(dst):], nil)
	if err != nil || string(back) != "prefix:hi" {
		t.Fatalf("Open append broken: %q %v", back, err)
	}

	// In-place operation.
	pt := []byte("in-place plaintext, longer than one block........")
	buf := make([]byte, 0, len(pt)+TagSize)
	buf = append(buf, pt...)
	sealed := aead.Seal(buf[:0], make([]byte, 12), buf, []byte("ad"))
	// Decrypt in place over the sealed buffer.
	opened, err := aead.Open(sealed[:0], make([]byte, 12), sealed, []byte("ad"))
	if err != nil || !bytes.Equal(opened, pt) {
		t.Fatalf("in-place round trip failed: %q %v", opened, err)
	}

	// Failed Open zeroes the output it wrote.
	bad := append([]byte{}, sealed...)
	bad[0] ^= 1
	dst = make([]byte, 0, len(bad)-TagSize)
	if _, err := aead.Open(dst, make([]byte, 12), bad, []byte("ad")); err == nil {
		t.Fatal("forged open accepted")
	} else if out := dst[:cap(dst)]; !bytes.Equal(out, make([]byte, len(out))) {
		t.Fatal("failed Open did not zero output")
	}
}

func requireHardwareAES(t testing.TB) {
	t.Helper()
	if !hardwareAES {
		t.Skip("hardware AES backend is unavailable")
	}
}

func mustPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	f()
}

func TestNewWithoutHardwareAES(t *testing.T) {
	if hardwareAES {
		t.Skip("run with purego or GODEBUG=cpu.aes=off")
	}
	for _, size := range []int{KeySize128, KeySize256} {
		if aead, err := New(make([]byte, size)); aead != nil || err != errHardwareAES {
			t.Fatalf("New(%d bytes) = %v, %v, want hardware AES error", size, aead, err)
		}
	}
}

func TestRFCLengthLimits(t *testing.T) {
	const limit = uint64(1 << 36)
	checkSealLengths(limit, limit)
	mustPanic(t, func() { checkSealLengths(limit+1, limit) })
	mustPanic(t, func() { checkSealLengths(limit, limit+1) })

	if !validOpenLengths(TagSize, 0) || !validOpenLengths(limit+TagSize, limit) {
		t.Fatal("Open rejected a boundary length")
	}
	if validOpenLengths(TagSize-1, 0) ||
		validOpenLengths(limit+TagSize+1, 0) ||
		validOpenLengths(TagSize, limit+1) {
		t.Fatal("Open accepted an out-of-range length")
	}
}

func TestBufferOverlap(t *testing.T) {
	requireHardwareAES(t)
	aead, err := New(make([]byte, KeySize256))
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, NonceSize, NonceSize+64)
	plaintext := []byte("hello")
	record := aead.Seal(nonce, nonce, plaintext, nil)
	if &record[0] != &nonce[0] || !bytes.Equal(record[:NonceSize], nonce) {
		t.Fatal("Seal failed to preserve the nonce prefix")
	}
	ciphertext := record[NonceSize:]
	opened, err := aead.Open(ciphertext[:0], record[:NonceSize], ciphertext, nil)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("in-place Open with adjacent nonce = %q, %v", opened, err)
	}

	dst := make([]byte, 64)
	mustPanic(t, func() { aead.Seal(dst[1:1], nonce, dst[:16], nil) })
	mustPanic(t, func() { aead.Seal(dst[:0], nonce, plaintext, dst[16:17]) })
	mustPanic(t, func() { aead.Seal(dst[:0], dst[:NonceSize], plaintext, nil) })
	mustPanic(t, func() { aead.Open(dst[1:1], nonce, dst[:32], nil) })
	mustPanic(t, func() { aead.Open(dst[:0], nonce, dst[16:48], dst[:1]) })
	mustPanic(t, func() { aead.Open(dst[:0], dst[:NonceSize], dst[16:48], nil) })
}

// ---------------------------------------------------------------------------
// RFC 8452 intermediate values (Sections 4, 8 and C.3)
// ---------------------------------------------------------------------------

func TestFieldDoubling(t *testing.T) {
	// RFC 8452, Appendix A: mulX examples.
	for _, tc := range []struct{ in, want string }{
		{"01000000000000000000000000000000", "02000000000000000000000000000000"},
		// Note: RFC 8452 prints ...ca5f2, corrected to ...ca572 by
		// verified erratum 5854 (the top bit folds back in per the
		// modulus x^128+x^127+x^126+x^121+1).
		{"9c98c04df9387ded828175a92ba652d8", "3931819bf271fada0503eb52574ca572"},
	} {
		var got [16]byte
		dbl(loadField(mustHex(t, tc.in))).store(got[:])
		if hex.EncodeToString(got[:]) != tc.want {
			t.Fatalf("dbl(%s) = %x, want %s", tc.in, got, tc.want)
		}
	}
}

func TestKDFIntermediate(t *testing.T) {
	requireHardwareAES(t)
	// RFC 8452, Appendix C.3: zero key and nonce.
	g, err := New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	var authKey [16]byte
	var sc scratchPad
	g.(*gcmsiv).deriveKeys(make([]byte, 12), &authKey, &sc.buf[0], &sc.buf[1])
	if got, want := hex.EncodeToString(authKey[:]), "dc95c078a24089895275f3d86b4fb868"; got != want {
		t.Fatalf("auth key = %s, want %s", got, want)
	}
}

func TestPOLYVALIntermediate(t *testing.T) {
	// RFC 8452, Appendix C.3: POLYVAL over the two plaintext blocks and the
	// length block, before the nonce xor and tag encryption.
	authKey := mustHex(t, "dc95c078a24089895275f3d86b4fb868")
	pt := mustHex(t, "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108")
	hp := dotKey(loadField(authKey))
	var got [16]byte
	polyval(hp, nil, pt).store(got[:])
	if want := "7367cdb411b730128dd56e8edc0eff56"; hex.EncodeToString(got[:]) != want {
		t.Fatalf("POLYVAL = %x, want %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// Independent POLYVAL cross-check via the GHASH relation (RFC 8452, App. A)
// ---------------------------------------------------------------------------

// The code below reimplements POLYVAL from scratch through GHASH, mirroring
// AWS-LC's polyval.c approach, to cross-check the table-free implementation:
// POLYVAL(H, Xs) = rev(GHASH(mulX_GHASH(rev(H)), rev(X1), ...)).
// GHASH uses MSB-first bit order with modulus x^128+x^7+x^2+x+1.

func rev16(b []byte) (out [16]byte) {
	for i := range out {
		out[i] = b[15-i]
	}
	return out
}

// ghashMulX multiplies a GHASH element by x. Validated against the RFC
// Appendix A examples in TestGHASHRelation.
func ghashMulX(a [16]byte) (out [16]byte) {
	hi := uint64(a[0])<<56 | uint64(a[1])<<48 | uint64(a[2])<<40 | uint64(a[3])<<32 |
		uint64(a[4])<<24 | uint64(a[5])<<16 | uint64(a[6])<<8 | uint64(a[7])
	lo := uint64(a[8])<<56 | uint64(a[9])<<48 | uint64(a[10])<<40 | uint64(a[11])<<32 |
		uint64(a[12])<<24 | uint64(a[13])<<16 | uint64(a[14])<<8 | uint64(a[15])
	lsb := lo & 1
	lo = lo>>1 | hi<<63
	hi >>= 1
	if lsb != 0 {
		hi ^= 0xE100000000000000
	}
	for i := 0; i < 8; i++ {
		out[i] = byte(hi >> (56 - 8*i))
		out[8+i] = byte(lo >> (56 - 8*i))
	}
	return out
}

// ghashMul multiplies two GHASH elements with schoolbook carryless
// multiplication in MSB-first order, reduced mod x^128+x^7+x^2+x+1.
// Bit p of z (0 = LSB) carries x^(255-p).
func ghashMul(a, b [16]byte) (out [16]byte) {
	ah := uint64(a[0])<<56 | uint64(a[1])<<48 | uint64(a[2])<<40 | uint64(a[3])<<32 |
		uint64(a[4])<<24 | uint64(a[5])<<16 | uint64(a[6])<<8 | uint64(a[7])
	al := uint64(a[8])<<56 | uint64(a[9])<<48 | uint64(a[10])<<40 | uint64(a[11])<<32 |
		uint64(a[12])<<24 | uint64(a[13])<<16 | uint64(a[14])<<8 | uint64(a[15])
	bh := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	bl := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	var z [4]uint64 // z[3] = top; bit p of z = x^(255-p)
	// For j = bit index MSB-first of a (x^j): z ^= b << (127-j) in x-exponent,
	// i.e. bit-shift of the 256-bit buffer by (127-j) towards the LSB.
	for j := 0; j < 128; j++ {
		var bit uint64
		if j < 64 {
			bit = (ah >> (63 - j)) & 1
		} else {
			bit = (al >> (127 - j)) & 1
		}
		if bit == 0 {
			continue
		}
		s := j // right shift: b*x^j moves each term j bits toward the LSB
		ws, bs := s/64, uint(s)%64
		var t [4]uint64
		src := [4]uint64{0, 0, bl, bh}
		for k := 0; k < 4; k++ {
			if k+ws < 4 {
				t[k] ^= src[k+ws] >> bs
			}
			if bs != 0 && k+ws+1 < 4 {
				t[k] ^= src[k+ws+1] << (64 - bs)
			}
		}
		for k := range z {
			z[k] ^= t[k]
		}
	}
	// Reduce x^254..x^128: x^k = x^(k-121)+x^(k-126)+x^(k-127)+x^(k-128).
	for k := 254; k >= 128; k-- {
		p := 255 - k
		if (z[p/64]>>(uint(p)%64))&1 == 0 {
			continue
		}
		z[p/64] ^= 1 << (uint(p) % 64)
		for _, d := range [4]int{121, 126, 127, 128} {
			q := 255 - (k - d)
			z[q/64] ^= 1 << (uint(q) % 64)
		}
	}
	out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7] =
		byte(z[3]>>56), byte(z[3]>>48), byte(z[3]>>40), byte(z[3]>>32),
		byte(z[3]>>24), byte(z[3]>>16), byte(z[3]>>8), byte(z[3])
	out[8], out[9], out[10], out[11], out[12], out[13], out[14], out[15] =
		byte(z[2]>>56), byte(z[2]>>48), byte(z[2]>>40), byte(z[2]>>32),
		byte(z[2]>>24), byte(z[2]>>16), byte(z[2]>>8), byte(z[2])
	return out
}

func polyvalViaGHASH(t *testing.T, h []byte, ad, data []byte) [16]byte {
	t.Helper()
	hg := ghashMulX(rev16(h))
	var s [16]byte
	feed := func(chunk []byte) {
		for i := range s {
			s[i] ^= chunk[i]
		}
		s = ghashMul(s, hg)
	}
	padded := func(data []byte) {
		for len(data) >= 16 {
			feed(data[:16])
			data = data[16:]
		}
		if len(data) > 0 {
			var blk [16]byte
			copy(blk[:], data)
			feed(blk[:])
		}
	}
	// GHASH input blocks are byte-reversed POLYVAL blocks.
	revBlocks := func(data []byte) []byte {
		out := make([]byte, 0, (len(data)+15)&^15)
		for len(data) >= 16 {
			r := rev16(data[:16])
			out = append(out, r[:]...)
			data = data[16:]
		}
		if len(data) > 0 {
			var blk [16]byte
			copy(blk[:], data)
			r := rev16(blk[:])
			out = append(out, r[:]...)
		}
		return out
	}
	padded(revBlocks(ad))
	padded(revBlocks(data))
	var lb [16]byte
	l := uint64(len(ad)) * 8
	for i := 0; i < 8; i++ {
		lb[i] = byte(l >> (8 * i))
	}
	l = uint64(len(data)) * 8
	for i := 8; i < 16; i++ {
		lb[i] = byte(l >> (8 * (i - 8)))
	}
	r := rev16(lb[:])
	feed(r[:])
	return rev16(s[:])
}

// clmul32Ref is a bit-by-bit carryless multiply used to check clmul32.
func clmul32Ref(a, b uint32) uint64 {
	var z uint64
	for i := 0; i < 32; i++ {
		if (a>>i)&1 != 0 {
			z ^= uint64(b) << i
		}
	}
	return z
}

func TestClmul32(t *testing.T) {
	edges := []uint32{0, 1, 2, 3, 0xff, 0x100, 0x11111111, 0x22222222, 0x44444444, 0x88888888, 0xdeadbeef, 0x80000000, 0x80000001, 0xffffffff, 0x7fffffff}
	for _, a := range edges {
		for _, b := range edges {
			if got, want := clmul32(a, b), clmul32Ref(a, b); got != want {
				t.Fatalf("clmul32(%x, %x) = %x, want %x", a, b, got, want)
			}
		}
	}
	rng := rand.New(rand.NewSource(0xC1A11))
	for i := 0; i < 200000; i++ {
		a, b := rng.Uint32(), rng.Uint32()
		if got, want := clmul32(a, b), clmul32Ref(a, b); got != want {
			t.Fatalf("clmul32(%x, %x) = %x, want %x", a, b, got, want)
		}
	}
}

func TestDotVsTables(t *testing.T) {
	rng := rand.New(rand.NewSource(0xD07))
	for i := 0; i < 200; i++ {
		h := field{rng.Uint64(), rng.Uint64()}
		var tab table4
		tab.build(dotKey(h))
		for j := 0; j < 5; j++ {
			s := field{rng.Uint64(), rng.Uint64()}
			if got, want := dot(s, h), tab.mul(s); got != want {
				t.Fatalf("iter %d/%d: dot %v, table %v", i, j, got, want)
			}
		}
		ad := make([]byte, rng.Intn(200))
		rng.Read(ad)
		data := make([]byte, rng.Intn(200))
		rng.Read(data)
		var want, got [16]byte
		polyval(dotKey(h), ad, data).store(want[:])
		polyvalDirect(h, ad, data).store(got[:])
		if got != want {
			t.Fatalf("iter %d: direct %x, table %x", i, got, want)
		}
	}
	// C.3 intermediate through the direct path too.
	authKey := mustHex(t, "dc95c078a24089895275f3d86b4fb868")
	pt := mustHex(t, "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108")
	var got [16]byte
	polyvalDirect(loadField(authKey), nil, pt).store(got[:])
	if want := "7367cdb411b730128dd56e8edc0eff56"; hex.EncodeToString(got[:]) != want {
		t.Fatalf("direct POLYVAL = %x, want %s", got, want)
	}
}

func TestGHASHRelation(t *testing.T) {
	// mulX_GHASH examples from RFC 8452, Appendix A.
	for _, tc := range []struct{ in, want string }{
		{"01000000000000000000000000000000", "00800000000000000000000000000000"},
		{"9c98c04df9387ded828175a92ba652d8", "4e4c6026fc9c3ef6c140bad495d3296c"},
	} {
		var raw [16]byte
		copy(raw[:], mustHex(t, tc.in))
		if got := ghashMulX(raw); hex.EncodeToString(got[:]) != tc.want {
			t.Fatalf("ghashMulX(%s) = %x, want %s", tc.in, got, tc.want)
		}
	}
	// C.3 POLYVAL result must match through the GHASH relation too.
	authKey := mustHex(t, "dc95c078a24089895275f3d86b4fb868")
	pt := mustHex(t, "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108")
	got := polyvalViaGHASH(t, authKey, nil, pt)
	if want := "7367cdb411b730128dd56e8edc0eff56"; hex.EncodeToString(got[:]) != want {
		t.Fatalf("GHASH-relation POLYVAL = %x, want %s", got, want)
	}
	// Randomized cross-check of the production implementation.
	rng := rand.New(rand.NewSource(0x5EED))
	for i := 0; i < 30; i++ {
		h := make([]byte, 16)
		rng.Read(h)
		ad := make([]byte, rng.Intn(100))
		rng.Read(ad)
		data := make([]byte, rng.Intn(100))
		rng.Read(data)
		want := polyvalViaGHASH(t, h, ad, data)
		var got [16]byte
		polyvalDirect(loadField(h), ad, data).store(got[:])
		if got != want {
			t.Fatalf("iter %d: mismatch\nrel %x\ngot %x", i, want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func benchmarkSeal(b *testing.B, ptLen, adLen int) {
	requireHardwareAES(b)
	b.Helper()
	aead, err := New(bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		b.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x01}, NonceSize)
	pt := bytes.Repeat([]byte{0x02}, ptLen)
	ad := bytes.Repeat([]byte{0x03}, adLen)
	b.SetBytes(int64(ptLen))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aead.Seal(nil, nonce, pt, ad)
	}
}

func benchmarkOpen(b *testing.B, ptLen, adLen int) {
	requireHardwareAES(b)
	b.Helper()
	aead, err := New(bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		b.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x01}, NonceSize)
	pt := bytes.Repeat([]byte{0x02}, ptLen)
	ad := bytes.Repeat([]byte{0x03}, adLen)
	ct := aead.Seal(nil, nonce, pt, ad)
	b.SetBytes(int64(ptLen))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := aead.Open(nil, nonce, ct, ad); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSeal16(b *testing.B)     { benchmarkSeal(b, 16, 0) }
func BenchmarkSeal64(b *testing.B)     { benchmarkSeal(b, 64, 0) }
func BenchmarkSeal512(b *testing.B)    { benchmarkSeal(b, 512, 0) }
func BenchmarkSeal4K(b *testing.B)     { benchmarkSeal(b, 4096, 0) }
func BenchmarkSeal16K(b *testing.B)    { benchmarkSeal(b, 16384, 0) }
func BenchmarkSeal64K(b *testing.B)    { benchmarkSeal(b, 65536, 0) }
func BenchmarkSeal1MAD12(b *testing.B) { benchmarkSeal(b, 1<<20, 12) }
func BenchmarkOpen16(b *testing.B)     { benchmarkOpen(b, 16, 0) }
func BenchmarkOpen64(b *testing.B)     { benchmarkOpen(b, 64, 0) }
func BenchmarkOpen512(b *testing.B)    { benchmarkOpen(b, 512, 0) }
func BenchmarkOpen4K(b *testing.B)     { benchmarkOpen(b, 4096, 0) }
func BenchmarkOpen16K(b *testing.B)    { benchmarkOpen(b, 16384, 0) }
func BenchmarkOpen64K(b *testing.B)    { benchmarkOpen(b, 65536, 0) }
func BenchmarkOpen1MAD12(b *testing.B) { benchmarkOpen(b, 1<<20, 12) }

func BenchmarkDeriveKeys(b *testing.B) {
	requireHardwareAES(b)
	g, _ := New(bytes.Repeat([]byte{0x77}, 32))
	nonce := bytes.Repeat([]byte{0x01}, NonceSize)
	var authKey [16]byte
	var sc scratchPad
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.(*gcmsiv).deriveKeys(nonce, &authKey, &sc.buf[0], &sc.buf[1])
	}
}
