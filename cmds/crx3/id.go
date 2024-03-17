package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/imishinist/go-crx3"
	"os"
)

func getAppIDFromCrx(crxFileName string) (string, error) {
	buf := new(bytes.Buffer)
	crxFile, err := os.Open(crxFileName)
	if err != nil {
		return "", err
	}
	defer crxFile.Close()

	header, err := crx3.SplitCrx(buf, crxFile)
	if err != nil {
		return "", err
	}
	if len(header.Sha256WithRsa) == 0 {
		return "", fmt.Errorf("no public key")
	}

	pk, err := x509.ParsePKIXPublicKey(header.Sha256WithRsa[0].PublicKey)
	if err != nil {
		return "", err
	}
	appid, err := crx3.AppIDFromPublicKey(pk.(*rsa.PublicKey))
	if err != nil {
		return "", err
	}
	return appid, nil
}

type idOpts struct {
	crxFile string
	keyFile string
}

func idCmd() command {
	fs := flag.NewFlagSet("id", flag.ExitOnError)

	opts := &idOpts{
		crxFile: "",
		keyFile: "",
	}
	fs.StringVar(&opts.crxFile, "crx", opts.crxFile, "CRX file to identify")
	fs.StringVar(&opts.keyFile, "key", opts.keyFile, "key file to identify")
	return command{
		fs: fs,
		fn: func(args []string) error {
			if err := fs.Parse(args); err != nil {
				return err
			}
			if opts.crxFile != "" {
				appid, err := getAppIDFromCrx(opts.crxFile)
				if err != nil {
					return err
				}
				fmt.Println(appid)
				return nil
			}

			if opts.keyFile != "" {
				key, err := crx3.LoadPrivateKey(opts.keyFile)
				if err != nil {
					return err
				}
				appid, err := crx3.AppIDFromPrivateKey(key)
				if err != nil {
					return err
				}
				fmt.Println(appid)
				return nil
			}

			return nil
		},
	}
}
