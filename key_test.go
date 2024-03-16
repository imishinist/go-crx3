package crx3_test

import (
	"testing"

	"github.com/imishinist/go-crx3"
)

func TestAppIDFromPrivateKey(t *testing.T) {
	key, err := crx3.LoadPrivateKey("./testdata/chrome-extension.pem")
	if err != nil {
		t.Fatal(err)
	}

	expected := "cdofnkkjddjieacnedgfcbndilidfihj"
	got, err := crx3.AppIDFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	if got != expected {
		t.Errorf("expected: %v, but got: %v", expected, got)
	}
}
