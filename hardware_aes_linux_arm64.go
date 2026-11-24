//go:build gc && !android && !purego && !goexperiment.boringcrypto

package gcmsiv

import (
	"golang.org/x/sys/cpu"
	"golang.org/x/sys/unix"
)

var hardwareAES = hasHardwareAES()

func hasHardwareAES() bool {
	if !cpu.ARM64.HasAES {
		return false
	}
	// Go's AES backend uses AT_HWCAP from the startup auxiliary vector.
	// Check that vector so x/sys/cpu's fallback probes cannot enable AES
	// when Go itself could not detect it.
	const atHWCAP = 16
	const hwcapAES = 1 << 3
	auxv, err := unix.Auxv()
	if err != nil {
		return false
	}
	for _, pair := range auxv {
		if pair[0] == atHWCAP {
			return pair[1]&hwcapAES != 0
		}
	}
	return false
}
