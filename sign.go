package crx3

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"

	"github.com/imishinist/go-crx3/pb"

	"google.golang.org/protobuf/proto"
)

const (
	crxMagic        = "Cr24"
	manifestVersion = 3
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
)

func SignTo(dest io.Writer, src io.ReadSeeker, key *rsa.PrivateKey) error {
	header, err := generateHeader(src, key)
	if err != nil {
		return err
	}

	// reset offset
	if _, err := src.Seek(0, 0); err != nil {
		return err
	}

	// write
	if _, err := dest.Write([]byte(crxMagic)); err != nil {
		return err
	}
	if err := binary.Write(dest, binary.LittleEndian, uint32(manifestVersion)); err != nil {
		return err
	}
	if err := binary.Write(dest, binary.LittleEndian, uint32(len(header))); err != nil {
		return err
	}
	if _, err := dest.Write(header); err != nil {
		return err
	}
	if _, err := io.Copy(dest, src); err != nil {
		return err
	}
	return nil
}

func generateHeader(data io.ReadSeeker, key *rsa.PrivateKey) ([]byte, error) {
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	signedData, err := proto.Marshal(&pb.SignedData{
		CrxId: generateCrxID(publicKey),
	})
	if err != nil {
		return nil, err
	}

	signature, err := sign(data, signedData, key)
	if err != nil {
		return nil, err
	}

	header, err := proto.Marshal(&pb.CrxFileHeader{
		Sha256WithRsa: []*pb.AsymmetricKeyProof{
			{
				PublicKey: publicKey,
				Signature: signature,
			},
		},
		SignedHeaderData: signedData,
	})
	if err != nil {
		return nil, err
	}
	return header, nil
}

func sign(r io.Reader, signedData []byte, pk *rsa.PrivateKey) ([]byte, error) {
	hashed, err := hashSignedData(r, signedData)
	if err != nil {
		return nil, err
	}

	return rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, hashed)
}

func hashSignedData(r io.Reader, signedData []byte) ([]byte, error) {
	sign := sha256.New()
	sign.Write([]byte("CRX3 SignedData\x00"))

	if err := binary.Write(sign, binary.LittleEndian, uint32(len(signedData))); err != nil {
		return nil, err
	}
	sign.Write(signedData)

	if _, err := io.Copy(sign, r); err != nil {
		return nil, err
	}
	return sign.Sum(nil), nil
}
