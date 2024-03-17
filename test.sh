#!/bin/bash

set -e

go build ./cmds/crx3
trap "rm -f crx3" EXIT


# id
diff -u \
  <(./crx3 id -key testdata/chrome-extension.pem) \
  <(./crx3 id -crx testdata/chrome-extension.crx)

dir=$(mktemp -d)

./crx3 pack \
  -output $dir/test.crx \
  -zip testdata/chrome-extension.zip \
  -key testdata/chrome-extension.pem
./crx3 unpack \
  -output $dir/test.zip \
  -crx $dir/test.crx

# pack/unpack
diff -u \
  <(cat testdata/chrome-extension.zip | openssl dgst) \
  <(cat $dir/test.zip | openssl dgst)

# id
diff -u \
  <(./crx3 id -key testdata/chrome-extension.pem) \
  <(./crx3 id -crx $dir/test.crx)

echo "OK"
