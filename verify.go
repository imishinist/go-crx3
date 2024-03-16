package crx3

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"io"

	"github.com/imishinist/go-crx3/pb"

	"google.golang.org/protobuf/proto"
)

const (
	metadataSize = 12
)

func VerifyAndExtract(dest io.Writer, data io.ReadSeeker) error {
	crx := make([]byte, metadataSize)
	if _, err := io.ReadFull(data, crx); err != nil {
		return err
	}

	// magic
	magic := string(crx[0:4])
	if magic != crxMagic {
		return ErrInvalidSignature
	}

	// manifest version
	version := binary.LittleEndian.Uint32(crx[4:8])
	if version != manifestVersion {
		return ErrInvalidSignature
	}

	// header size
	headerSize := binary.LittleEndian.Uint32(crx[8:12])
	headerBytes := make([]byte, headerSize)
	if _, err := io.ReadFull(data, headerBytes); err != nil {
		return err
	}

	// unmarshal
	var (
		header     pb.CrxFileHeader
		signedData pb.SignedData
	)
	if err := proto.Unmarshal(headerBytes, &header); err != nil {
		return err
	}
	if err := proto.Unmarshal(header.SignedHeaderData, &signedData); err != nil {
		return err
	}

	// verify
	if len(signedData.CrxId) != crxIDLength {
		return ErrInvalidSignature
	}
	for _, r := range header.Sha256WithRsa {
		if err := verify(data, header.SignedHeaderData, r.PublicKey, r.Signature); err != nil {
			return err
		}
		if _, err := data.Seek(metadataSize+int64(headerSize), io.SeekStart); err != nil {
			return err
		}
	}
	if _, err := io.Copy(dest, data); err != nil {
		return err
	}
	return nil
}

func verify(r io.Reader, signedData, publicKey, signature []byte) error {
	pk, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	hashed, err := hashSignedData(r, signedData)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(pk.(*rsa.PublicKey), crypto.SHA256, hashed, signature)
}
