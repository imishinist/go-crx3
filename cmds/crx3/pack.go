package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/imishinist/go-crx3"
)

func pack(outputTo, zipFile, keyFile string) error {
	file, err := os.Open(zipFile)
	if err != nil {
		return err
	}
	defer file.Close()

	key, err := crx3.LoadPrivateKey(keyFile)
	if err != nil {
		return err
	}

	dest, err := os.OpenFile(outputTo, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer dest.Close()

	if err := crx3.SignTo(dest, file, key); err != nil {
		return err
	}
	return nil
}

type packOpts struct {
	outputTo string
	zipFile  string
	keyFile  string
}

func packCmd() command {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)

	opts := &packOpts{
		outputTo: "",
		zipFile:  "",
		keyFile:  "",
	}
	fs.StringVar(&opts.outputTo, "output", opts.outputTo, "output file")
	fs.StringVar(&opts.zipFile, "zip", opts.outputTo, "zip file to sign")
	fs.StringVar(&opts.keyFile, "key", opts.outputTo, "key file to sign")
	return command{
		fs: fs,
		fn: func(args []string) error {
			if err := fs.Parse(args); err != nil {
				return err
			}
			if opts.outputTo == "" || opts.zipFile == "" || opts.keyFile == "" {
				return fmt.Errorf("output, zip and key are required")
			}
			return pack(opts.outputTo, opts.zipFile, opts.keyFile)
		},
	}
}
