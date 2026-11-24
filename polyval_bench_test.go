package gcmsiv

import (
	"crypto/aes"
	"strconv"
	"testing"
)

func BenchmarkNewCipher256(b *testing.B) {
	k := make([]byte, 32)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := aes.NewCipher(k); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTable4Build(b *testing.B) {
	h := field{0x1234, 0x5678}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var t table4
		t.build(h)
	}
}

func BenchmarkTable4Mul(b *testing.B) {
	var t table4
	t.build(field{0x1234, 0x5678})
	s := field{0xdeadbeef, 0xcafef00d}
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s = t.mul(s)
	}
}

func BenchmarkDot(b *testing.B) {
	a := field{0xdeadbeef, 0xcafef00d}
	h := field{0x1234, 0x5678}
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a = dot(a, h)
	}
}

func BenchmarkPolyvalDirectN(b *testing.B) {
	for _, n := range []int{1, 2, 4, 8, 12, 16, 24, 32} {
		h := field{0x1234, 0x5678}
		data := make([]byte, 16*n)
		b.Run(itoa(n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				polyvalDirect(h, nil, data)
			}
		})
	}
}

func BenchmarkPolyvalTableN(b *testing.B) {
	for _, n := range []int{1, 2, 4, 8, 12, 16, 24, 32} {
		hp := dotKey(field{0x1234, 0x5678})
		data := make([]byte, 16*n)
		b.Run(itoa(n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				polyval(hp, nil, data)
			}
		})
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
