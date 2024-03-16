package main

import (
	"flag"
	"fmt"
	"github.com/imishinist/go-crx3"
	"io"
	"os"
)

func unpack(outputTo string, crxFile string) error {
	file, err := os.Open(crxFile)
	if err != nil {
		return err
	}
	defer file.Close()

	dest, err := os.OpenFile(outputTo, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer dest.Close()

	if _, err = crx3.ExtractHeader(file); err != nil {
		return err
	}
	if _, err = io.Copy(dest, file); err != nil {
		return err
	}

	return nil
}

type unpackOpts struct {
	outputTo string
	crxFile  string
}

func unpackCmd() command {
	fs := flag.NewFlagSet("unpack", flag.ExitOnError)

	opts := &unpackOpts{
		outputTo: "",
		crxFile:  "",
	}
	fs.StringVar(&opts.outputTo, "output", opts.outputTo, "output file")
	fs.StringVar(&opts.crxFile, "crx", opts.crxFile, "crx file")
	return command{
		fs: fs,
		fn: func(args []string) error {
			if err := fs.Parse(args); err != nil {
				return err
			}
			if opts.outputTo == "" || opts.crxFile == "" {
				return fmt.Errorf("output and crx are required")
			}
			return unpack(opts.outputTo, opts.crxFile)
		},
	}
}
