package keystore

import "fmt"

// Keystore describes the input parameters to the scrypt
// key derivation function as per Colin Percival's scrypt
// paper: http://www.tarsnap.com/scrypt/scrypt.pdf
type Keystore struct {
	N       int // CPU/memory cost parameter (logN)
	R       int // block size parameter (octets)
	P       int // parallelisation parameter (positive int)
	SaltLen int // bytes to use as salt (octets)
	DKLen   int // length of the derived key (octets)

	keystore map[string]string
}

// DefaultKeystore provides sensible default inputs into the scrypt function
// for interactive use (i.e. web applications).
// These defaults will consume approxmiately 16MB of memory (128 * r * N).
// The default key length is 256 bits.
var DefaultKeystore = Keystore{N: 16384, R: 8, P: 1, SaltLen: 16, DKLen: 32}

func (gks Keystore) load(fileName string, kek []byte) error {
	return fmt.Errorf("test")
}
