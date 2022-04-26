package securestorage

import (
	"bytes"
	"testing"
)

func TestBytes(t *testing.T) {
	plain := []byte("test")

	key := []byte("password")

	t.Log("plaintext: ", plain)

	ct, err := SaveBytes(key, plain)
	if err != nil {
		t.Fatalf("Error encrypting plaintext: %c", err)
	}

	t.Log("ciphertext: ", ct)

	pt, err := LoadBytes(key, ct)
	if err != nil {
		t.Fatalf("Error decrypting ciphertext: %v", err)
	}
	t.Log("recovered text:", pt)

	if !bytes.Equal(plain, pt) {
		t.Fatalf("Decrypted plaintext does not match expected plaintext. Expected \"%d\" got \"%d\"", plain, pt)
	}
}
