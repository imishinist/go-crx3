package crx3

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strconv"
)

const (
	crxIDLength = 16
)

func GenerateNewKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func AppIDFromPublicKey(key *rsa.PublicKey) (string, error) {
	publicKey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write(publicKey)
	hashed := hash.Sum(nil)

	ret := ""
	for _, b := range fmt.Sprintf("%x", hashed[0:crxIDLength]) {
		n, _ := strconv.ParseInt(fmt.Sprintf("%c", b), 16, 32)
		ret += fmt.Sprintf("%s", strconv.FormatInt(n+0x0a, 26))
	}
	return ret, nil
}

func AppIDFromPrivateKey(key *rsa.PrivateKey) (string, error) {
	return AppIDFromPublicKey(&key.PublicKey)
}

func CrxIDFromPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	return generateCrxID(publicKey), nil
}

func generateCrxID(publicKey []byte) []byte {
	hash := sha256.New()
	hash.Write(publicKey)
	return hash.Sum(nil)[0:16]
}

func ParsePrivateKey(in io.Reader) (*rsa.PrivateKey, error) {
	buf, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, fmt.Errorf("failed to decode as pem")
	}

	r, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return r.(*rsa.PrivateKey), nil
}

func LoadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return ParsePrivateKey(file)
}
