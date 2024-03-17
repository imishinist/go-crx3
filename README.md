# go-crx3

This is a library that can handle Chrome Extension with the io.Reader,
io.Writer interface.

It also provides a tool to pack and unpack extensions.

## Usage

```
go get -u github.com/imishinist/go-crx3
```

## Example

```golang
package main

import (
	"log"
	"os"

	"github.com/imishinist/go-crx3"
)

func main() {
	zipFile := "/path/to/extension.zip"
	keyFile := "/path/to/key.pem"
	crxFile := "/path/to/extension.crx"

	r, err := os.Open(zipFile)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	key, err := crx3.LoadPrivateKey(keyFile)
	if err != nil {
		log.Fatal(err)
	}

	w, err := os.Create(crxFile)
	if err != nil {
		log.Fatal(err)
	}
	defer w.Close()

	if err := crx3.SignTo(w, r, key); err != nil {
		log.Fatal(err)
	}
}
```

## download proto file

```
curl -O https://raw.githubusercontent.com/chromium/chromium/main/components/crx_file/crx3.proto
```

## Support

- chrome extension - version 3
    - one rsa key only

ECDSA not supported.

