package crx3

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/imishinist/go-crx3/pb"

	"google.golang.org/protobuf/proto"
)

const (
	metadataSize = 12
)

func SplitCrx(dest io.Writer, crxData io.ReadSeeker) (*pb.CrxFileHeader, error) {
	crx := make([]byte, metadataSize)
	if _, err := io.ReadFull(crxData, crx); err != nil {
		return nil, err
	}

	// magic
	magic := string(crx[0:4])
	if magic != crxMagic {
		return nil, ErrInvalidSignature
	}

	// manifest version
	version := binary.LittleEndian.Uint32(crx[4:8])
	if version != manifestVersion {
		return nil, ErrInvalidSignature
	}

	// header size
	headerSize := binary.LittleEndian.Uint32(crx[8:12])
	headerBytes := make([]byte, headerSize)
	if _, err := io.ReadFull(crxData, headerBytes); err != nil {
		return nil, err
	}

	// unmarshal
	var (
		header     pb.CrxFileHeader
		signedData pb.SignedData
	)
	if err := proto.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(header.SignedHeaderData, &signedData); err != nil {
		return nil, err
	}

	// verify
	if len(signedData.CrxId) != crxIDLength {
		return nil, ErrInvalidSignature
	}

	if _, err := io.Copy(dest, crxData); err != nil {
		return nil, err
	}

	return &header, nil
}

func VerifyAndExtract(dest io.Writer, crxData io.ReadSeeker) error {
	buf := new(bytes.Buffer)
	header, err := SplitCrx(buf, crxData)
	if err != nil {
		return err
	}

	if len(header.Sha256WithRsa) == 0 {
		return fmt.Errorf("RSA signature is not found")
	}
	if len(header.Sha256WithRsa) > 1 {
		return fmt.Errorf("multiple RSA signature is not supported")
	}
	if len(header.Sha256WithEcdsa) > 0 {
		return fmt.Errorf("ECDSA signature is not supported")
	}

	bufReader := bytes.NewReader(buf.Bytes())
	for _, r := range header.Sha256WithRsa {
		if err := verify(buf, header.SignedHeaderData, r.PublicKey, r.Signature); err != nil {
			return err
		}
		if _, err := bufReader.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}
	if _, err := io.Copy(dest, bufReader); err != nil {
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
