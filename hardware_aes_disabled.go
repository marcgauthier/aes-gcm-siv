//go:build !gc || purego || goexperiment.boringcrypto || (!amd64 && !(linux && arm64 && !android))

package gcmsiv

const hardwareAES = false
