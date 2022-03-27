package xt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"

	"github.com/go-acme/lego/v4/certcrypto"
)

const (
	KeyInvalid = iota
	KeyRSA2048
	KeyRSA4096
	KeyRSA8192
	KeyEC256
	KeyEC384
)

var (
	KeyUnknown = certcrypto.KeyType("UNKNOWN")
	nameToType = map[string]int{
		"rsa2048": KeyRSA2048,
		"rsa4096": KeyRSA4096,
		"rsa8192": KeyRSA8192,
		"ec256":   KeyEC256,
		"ec384":   KeyEC384,
	}
	typeToCr = map[int]certcrypto.KeyType{
		KeyRSA2048: certcrypto.RSA2048,
		KeyRSA4096: certcrypto.RSA4096,
		KeyRSA8192: certcrypto.RSA8192,
		KeyEC256:   certcrypto.EC256,
		KeyEC384:   certcrypto.EC384,
	}
)

func keyEC(k *ecdsa.PrivateKey) int {
	switch k.Params().BitSize {
	case 384:
		return KeyEC384
	case 256:
		return KeyEC256
	default:
		return KeyInvalid
	}
}

func keyRSA(k *rsa.PrivateKey) int {
	switch k.Size() {
	case 256:
		return KeyRSA2048
	case 512:
		return KeyRSA4096
	case 1024:
		return KeyRSA8192
	default:
		return KeyInvalid
	}
}

func KeyType(key crypto.PrivateKey) int {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return keyEC(k)
	case *rsa.PrivateKey:
		return keyRSA(k)
	default:
		return KeyInvalid
	}
}

func KeyFromName(name string) int {
	if v, ok := nameToType[name]; ok {
		return v
	}
	return KeyInvalid
}

func KeyToCr(t int) certcrypto.KeyType {
	if v, ok := typeToCr[t]; ok {
		return v
	}
	return KeyUnknown
}

func KeyTypeCr(key crypto.PrivateKey) certcrypto.KeyType {
	return KeyToCr(KeyType(key))
}

func LoadKey(name string) (crypto.PrivateKey, int, error) {
	if len(name) == 0 {
		return nil, KeyInvalid, fmt.Errorf("invalid file name")
	}
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, KeyInvalid, err
	}
	key, err := certcrypto.ParsePEMPrivateKey(data)
	if err != nil {
		return nil, KeyInvalid, err
	}
	n := KeyType(key)
	if n == KeyInvalid {
		return nil, KeyInvalid, fmt.Errorf("invalid key type")
	}
	return key, n, nil
}

func LoadKeyCr(name string) (crypto.PrivateKey, certcrypto.KeyType, error) {
	key, n, err := LoadKey(name)
	return key, KeyToCr(n), err
}

func SaveKey(name string, key crypto.PrivateKey) error {
	if len(name) == 0 {
		return fmt.Errorf("invalid file name")
	}
	data := certcrypto.PEMEncode(key)
	if len(data) == 0 {
		return fmt.Errorf("invalid key")
	}
	return ioutil.WriteFile(name, data, 0600)
}

func GenKey(n int) (crypto.PrivateKey, error) {
	switch n {
	case KeyEC256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyEC384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case KeyRSA8192:
		return rsa.GenerateKey(rand.Reader, 8192)
	default:
		return nil, fmt.Errorf("invalid key type")
	}
}

func GenKeyCr(t certcrypto.KeyType) (crypto.PrivateKey, error) {
	return certcrypto.GeneratePrivateKey(t)
}
