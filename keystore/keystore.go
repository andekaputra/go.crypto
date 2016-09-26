package keystore

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"time"

	"golang.org/x/crypto/scrypt"
)

// KeyStore represents a interface contract of a key store
type KeyStore interface {
	getKey(alias string, password string) (entry *KeyEntry, err error)
	setKey(alias string, password string, entry *KeyEntry) (err error)
	getProvider() string
	size() int
}

// KeyEntry represents an entry in a KeyStore
type KeyEntry struct {
	algorithm  string
	publicKey  crypto.PublicKey
	privateKey crypto.PrivateKey
	key        []byte
	attributes map[string]string
}

// FileBasedKeyStore simple implementation of a filesystem based key store
type FileBasedKeyStore struct {
}

const (
	defaulKeyStoreProvider    = "default"
	defaultKeyStoreEncryption = "AESGCM256"
)

var (
	keys                map[string]KeyEntry
	defaultScryptParams = scryptParams{N: 16384, R: 8, P: 1, Salt: ""}
)

type keystoreJSON struct {
	Size    int       `json:"size"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
	Records []struct {
		Alias      string    `json:"alias"`
		Type       string    `json:"type"`
		Algorithm  string    `json:"algorithm"`
		Value      string    `json:"value"`
		Password   string    `json:"password"`
		Entered    time.Time `json:"entered"`
		Attributes struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"attributes"`
	} `json:"records"`
}

type scryptParams struct {
	N    int    `json:"n"`
	R    int    `json:"r"`
	P    int    `json:"p"`
	Salt string `json:"salt"`
}

type keystoreFile struct {
	Scrypt scryptParams `json:"scrypt"`
	Iv     string       `json:"iv"`
	Cipher string       `json:"cipher"`
}

func (ks *FileBasedKeyStore) getKey(alias string, password string) (entry *KeyEntry, err error) {
	return nil, nil
}

func (ks *FileBasedKeyStore) setKey(alias string, password string, entry KeyEntry) (err error) {
	return nil
}

func (ks *FileBasedKeyStore) getProvider() string {
	return defaulKeyStoreProvider
}

func (ks *FileBasedKeyStore) size() int {
	return len(keys)
}

// CreateKeyStore creates an empty key store file
func CreateKeyStore(filename string, password string, sp *scryptParams,
	overwrite bool) (err error) {
	fileinfo, ex := os.Stat(filename)
	if (ex == nil && (!overwrite || fileinfo.IsDir())) || os.IsPermission(ex) {
		return errors.New("Key store file already exists or file permission issue!")
	}

	var _sp scryptParams
	if sp == nil {
		_sp = defaultScryptParams
	} else {
		_sp = *sp
	}

	var salt []byte
	if _sp.Salt == "" {
		salt = make([]byte, 16)
		_, ex = rand.Read(salt)
		if ex != nil {
			return ex
		}
	} else {
		salt, ex = hex.DecodeString(_sp.Salt)
		if ex != nil {
			return ex
		}
	}

	dk, ex := scrypt.Key([]byte(password), salt, _sp.N, _sp.R, _sp.P, 32)
	if ex != nil {
		return ex
	}

	iv := make([]byte, 12)
	_, ex = rand.Read(iv)
	if ex != nil {
		return ex
	}

	now := time.Now()
	keystoreJSONStruct := keystoreJSON{Size: 0, Created: now, Updated: now}
	marshalledJSON, ex := json.Marshal(keystoreJSONStruct)
	if ex != nil {
		return ex
	}

	aesBlock, ex := aes.NewCipher(dk)
	if ex != nil {
		return ex
	}

	aesgcm, ex := cipher.NewGCM(aesBlock)
	if ex != nil {
		return ex
	}

	ciphertext := aesgcm.Seal(nil, iv, marshalledJSON, nil)

	keystoreFileJSON := keystoreFile{scryptParams{_sp.N, _sp.R, _sp.P, hex.EncodeToString(salt)},
		hex.EncodeToString(iv), hex.EncodeToString(ciphertext)}

	marshalledJSON, ex = json.Marshal(keystoreFileJSON)
	if ex != nil {
		return ex
	}

	ex = ioutil.WriteFile(filename, marshalledJSON, 0644)
	if ex != nil {
		return ex
	}

	return nil
}
