package identity

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestGenerate_AppIDIsHexOfPublicKey(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	expected := hex.EncodeToString(id.PublicKey)
	if id.AppID != expected {
		t.Errorf("AppID = %q, want hex of public key %q", id.AppID, expected)
	}
}

func TestFromPrivateKey_RoundTrip(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	seed := id.privateKey.Seed()

	id2, err := FromPrivateKey(seed)
	if err != nil {
		t.Fatalf("FromPrivateKey() error: %v", err)
	}

	if id2.AppID != id.AppID {
		t.Errorf("AppID mismatch: got %q, want %q", id2.AppID, id.AppID)
	}
	if hex.EncodeToString(id2.PublicKey) != hex.EncodeToString(id.PublicKey) {
		t.Error("PublicKey mismatch after round-trip")
	}
}

func TestFromPrivateKey_InvalidSeedSize(t *testing.T) {
	_, err := FromPrivateKey([]byte("tooshort"))
	if err == nil {
		t.Error("expected error for invalid seed size, got nil")
	}
}

func TestSign_ProducesVerifiableSignature(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	data := []byte("hello mft")
	sig := id.Sign(data)

	if !ed25519.Verify(id.PublicKey, data, sig) {
		t.Error("signature produced by Sign() is not valid")
	}
}

func TestVerify_ValidSignature(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	data := []byte("hello mft")
	sig := id.Sign(data)

	if !id.Verify(data, sig) {
		t.Error("Verify() returned false for valid signature")
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	data := []byte("hello mft")
	sig := id.Sign(data)
	sig[0] ^= 0xff // corrompt la signature

	if id.Verify(data, sig) {
		t.Error("Verify() returned true for corrupted signature")
	}
}
