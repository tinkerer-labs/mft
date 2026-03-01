// Package identity
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

type Identity struct {
	AppID      string
	PublicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func Generate() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	return &Identity{
		AppID:      hex.EncodeToString(pub),
		PublicKey:  pub,
		privateKey: priv,
	}, nil
}

func FromPrivateKey(seed []byte) (*Identity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed size: got %d, want %d", len(seed), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	return &Identity{
		AppID:      hex.EncodeToString(pub),
		PublicKey:  pub,
		privateKey: priv,
	}, nil
}

func (id *Identity) Seed() []byte {
	return id.privateKey.Seed()
}

func (id *Identity) Sign(data []byte) []byte {
	return ed25519.Sign(id.privateKey, data)
}

func (id *Identity) Verify(data, sig []byte) bool {
	return ed25519.Verify(id.PublicKey, data, sig)
}
