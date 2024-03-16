package crx3

import (
	"encoding/binary"
	"github.com/imishinist/go-crx3/pb"
	"google.golang.org/protobuf/proto"
	"io"
)

const (
	metadataSize = 12
)

func ExtractHeader(data io.ReadSeeker) (*pb.CrxFileHeader, error) {
	crx := make([]byte, metadataSize)
	if _, err := io.ReadFull(data, crx); err != nil {
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
	if _, err := io.ReadFull(data, headerBytes); err != nil {
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

	if len(signedData.CrxId) != crxIDLength {
		return nil, ErrInvalidSignature
	}

	return &header, nil
}
