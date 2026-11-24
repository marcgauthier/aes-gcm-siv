//go:build gc && !purego && !goexperiment.boringcrypto

package gcmsiv

import "golang.org/x/sys/cpu"

// Match crypto/aes's hardware dispatch. Require the additional x86
// features used by newer Go versions even when building with older Go.
// The CPU feature flags also honor GODEBUG CPU settings at startup.
var hardwareAES = cpu.X86.HasAES && cpu.X86.HasSSSE3 && cpu.X86.HasSSE41
