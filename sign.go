package crx3

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"io"

	"github.com/imishinist/go-crx3/pb"

	"google.golang.org/protobuf/proto"
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
	if _, err := dest.Write([]byte("Cr24")); err != nil {
		return err
	}
	if err := binary.Write(dest, binary.LittleEndian, uint32(3)); err != nil {
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
	sign := sha256.New()
	// magic
	sign.Write([]byte("CRX3 SignedData\x00"))

	// signed data
	if err := binary.Write(sign, binary.LittleEndian, uint32(len(signedData))); err != nil {
		return nil, err
	}
	sign.Write(signedData)

	// body
	if _, err := io.Copy(sign, r); err != nil {
		return nil, err
	}

	return rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, sign.Sum(nil))
}
