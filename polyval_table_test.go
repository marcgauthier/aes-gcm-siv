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

import "encoding/binary"

// The table-based implementation serves as a test and benchmark reference.
// xinvValue is x^-128 = x^127 + x^124 + x^121 + x^114 + 1
// (RFC 8452, Section 3).
var xinvValue = field{lo: 1, hi: 0x9204000000000000}

// xinvTable holds nibble multiplication tables for the constant x^-128,
// used to derive H' = H * x^-128 once per message. It is built once at
// init time and read-only afterwards.
var xinvTable table4

func init() {
	xinvTable.build(xinvValue)
}

// dotKey returns H' = H * x^-128, so that dot(s, H) == mul(s, H').
func dotKey(h field) field {
	return xinvTable.mul(h)
}

// table4 holds 32 nibble tables for plain field multiplication by a fixed
// key: t[i][v] = key * (v * x^(4*i)).
type table4 struct {
	t [32][16]field
}

func (t *table4) build(h field) {
	// First derive all T[i][1] = h*x^(4*i) through one doubling chain,
	// then fill in the remaining entries table by table. The fills are
	// independent of each other, which lets the CPU overlap them.
	t.t[0][0] = field{}
	t.t[0][1] = h
	x := h
	for i := 1; i < 32; i++ {
		x = dbl(dbl(dbl(dbl(x))))
		t.t[i][0] = field{}
		t.t[i][1] = x
	}
	for i := 0; i < 32; i++ {
		x := t.t[i][1]
		t2 := dbl(x)
		t.t[i][2], t.t[i][3] = t2, t2.xor(x)
		t4 := dbl(t2)
		t.t[i][4], t.t[i][5] = t4, t4.xor(x)
		t6 := dbl(t.t[i][3])
		t.t[i][6], t.t[i][7] = t6, t6.xor(x)
		t8 := dbl(t4)
		t.t[i][8], t.t[i][9] = t8, t8.xor(x)
		t10 := dbl(t.t[i][5])
		t.t[i][10], t.t[i][11] = t10, t10.xor(x)
		t12 := dbl(t6)
		t.t[i][12], t.t[i][13] = t12, t12.xor(x)
		t14 := dbl(t.t[i][7])
		t.t[i][14], t.t[i][15] = t14, t14.xor(x)
	}
}

// mul returns s * key using the precomputed tables. Fully unrolled with
// four accumulators to expose instruction-level parallelism.
func (t *table4) mul(s field) field {
	lo, hi := s.lo, s.hi
	var r0, r1, r2, r3 field
	e := t.t[0][lo&0xf]
	r0.lo, r0.hi = e.lo, e.hi
	e = t.t[1][(lo>>4)&0xf]
	r1.lo, r1.hi = e.lo, e.hi
	e = t.t[2][(lo>>8)&0xf]
	r2.lo, r2.hi = e.lo, e.hi
	e = t.t[3][(lo>>12)&0xf]
	r3.lo, r3.hi = e.lo, e.hi
	e = t.t[4][(lo>>16)&0xf]
	r0.lo ^= e.lo
	r0.hi ^= e.hi
	e = t.t[5][(lo>>20)&0xf]
	r1.lo ^= e.lo
	r1.hi ^= e.hi
	e = t.t[6][(lo>>24)&0xf]
	r2.lo ^= e.lo
	r2.hi ^= e.hi
	e = t.t[7][(lo>>28)&0xf]
	r3.lo ^= e.lo
	r3.hi ^= e.hi
	e = t.t[8][(lo>>32)&0xf]
	r0.lo ^= e.lo
	r0.hi ^= e.hi
	e = t.t[9][(lo>>36)&0xf]
	r1.lo ^= e.lo
	r1.hi ^= e.hi
	e = t.t[10][(lo>>40)&0xf]
	r2.lo ^= e.lo
	r2.hi ^= e.hi
	e = t.t[11][(lo>>44)&0xf]
	r3.lo ^= e.lo
	r3.hi ^= e.hi
	e = t.t[12][(lo>>48)&0xf]
	r0.lo ^= e.lo
	r0.hi ^= e.hi
	e = t.t[13][(lo>>52)&0xf]
	r1.lo ^= e.lo
	r1.hi ^= e.hi
	e = t.t[14][(lo>>56)&0xf]
	r2.lo ^= e.lo
	r2.hi ^= e.hi
	e = t.t[15][(lo>>60)&0xf]
	r3.lo ^= e.lo
	r3.hi ^= e.hi
	e = t.t[16][hi&0xf]
	r0.lo ^= e.lo
	r0.hi ^= e.hi
	e = t.t[17][(hi>>4)&0xf]
	r1.lo ^= e.lo
	r1.hi ^= e.hi
	e = t.t[18][(hi>>8)&0xf]
	r2.lo ^= e.lo
	r2.hi ^= e.hi
	e = t.t[19][(hi>>12)&0xf]
	r3.lo ^= e.lo
	r3.hi ^= e.hi
	e = t.t[20][(hi>>16)&0xf]
	r0.lo ^= e.lo
	r0.hi ^= e.hi
	e = t.t[21][(hi>>20)&0xf]
	r1.lo ^= e.lo
	r1.hi ^= e.hi
	e = t.t[22][(hi>>24)&0xf]
	r2.lo ^= e.lo
	r2.hi ^= e.hi
	e = t.t[23][(hi>>28)&0xf]
	r3.lo ^= e.lo
	r3.hi ^= e.hi
	e = t.t[24][(hi>>32)&0xf]
	r0.lo ^= e.lo
	r0.hi ^= e.hi
	e = t.t[25][(hi>>36)&0xf]
	r1.lo ^= e.lo
	r1.hi ^= e.hi
	e = t.t[26][(hi>>40)&0xf]
	r2.lo ^= e.lo
	r2.hi ^= e.hi
	e = t.t[27][(hi>>44)&0xf]
	r3.lo ^= e.lo
	r3.hi ^= e.hi
	e = t.t[28][(hi>>48)&0xf]
	r0.lo ^= e.lo
	r0.hi ^= e.hi
	e = t.t[29][(hi>>52)&0xf]
	r1.lo ^= e.lo
	r1.hi ^= e.hi
	e = t.t[30][(hi>>56)&0xf]
	r2.lo ^= e.lo
	r2.hi ^= e.hi
	e = t.t[31][(hi>>60)&0xf]
	r3.lo ^= e.lo
	r3.hi ^= e.hi
	return field{
		lo: r0.lo ^ r1.lo ^ r2.lo ^ r3.lo,
		hi: r0.hi ^ r1.hi ^ r2.hi ^ r3.hi,
	}
}

// update runs the POLYVAL iteration over whole blocks: s = (s + X) * key.
func (t *table4) update(s field, data []byte) field {
	for len(data) >= 16 {
		s.lo ^= binary.LittleEndian.Uint64(data)
		s.hi ^= binary.LittleEndian.Uint64(data[8:])
		s = t.mul(s)
		data = data[16:]
	}
	return s
}

// polyval evaluates POLYVAL with dot-key hp over ad, data and the
// length block.
func polyval(hp field, ad, data []byte) field {
	var t table4
	t.build(hp)
	s := field{}
	s = t.update(s, ad)
	if rem := len(ad) & 15; rem != 0 {
		var blk [16]byte
		copy(blk[:], ad[len(ad)-rem:])
		s = s.xor(loadField(blk[:]))
		s = t.mul(s)
	}
	s = t.update(s, data)
	if rem := len(data) & 15; rem != 0 {
		var blk [16]byte
		copy(blk[:], data[len(data)-rem:])
		s = s.xor(loadField(blk[:]))
		s = t.mul(s)
	}
	var lb [16]byte
	binary.LittleEndian.PutUint64(lb[:], uint64(len(ad))*8)
	binary.LittleEndian.PutUint64(lb[8:], uint64(len(data))*8)
	s = s.xor(loadField(lb[:]))
	return t.mul(s)
}
