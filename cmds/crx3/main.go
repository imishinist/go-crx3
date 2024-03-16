package main

import (
	"flag"
	"log"
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

func main() {
	var (
		outputTo string
		zipFile  string
		keyFile  string
	)
	flag.StringVar(&outputTo, "output", "", "output file")
	flag.StringVar(&zipFile, "zip", "", "zip file to sign")
	flag.StringVar(&keyFile, "key", "", "key file to sign")

	flag.Parse()
	if outputTo == "" || zipFile == "" || keyFile == "" {
		flag.Usage()
		return
	}

	if err := pack(outputTo, zipFile, keyFile); err != nil {
		log.Fatal(err)
	}
}
