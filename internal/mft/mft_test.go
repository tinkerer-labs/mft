package mft

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha3"
	"os"
	"testing"
)

// ===== HELPERS =====

func generateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "mft-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

// ===== BuildFromFile =====

// TestBuildFromFile_BasicFields vérifie que les champs de base sont correctement initialisés.
func TestBuildFromFile_BasicFields(t *testing.T) {
	data := bytes.Repeat([]byte{0x42}, 1024)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, err := buildFromFile(path, privKey, 512)
	if err != nil {
		t.Fatalf("buildFromFile: %v", err)
	}

	if string(m.Header.Magic[:]) != MagicMFT {
		t.Errorf("Header.Magic = %q, want %q", m.Header.Magic, MagicMFT)
	}
	if m.Header.Version != VersionMFT {
		t.Errorf("Header.Version = %d, want %d", m.Header.Version, VersionMFT)
	}
	if m.Content.Size != uint64(len(data)) {
		t.Errorf("Content.Size = %d, want %d", m.Content.Size, len(data))
	}
	if m.Content.ChunkSize != 512 {
		t.Errorf("Content.ChunkSize = %d, want 512", m.Content.ChunkSize)
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(m.Author[:], pubKey) {
		t.Error("Author does not match public key from privKey")
	}
}

// TestBuildFromFile_ChunkLayout vérifie le découpage en chunks : nombre, taille du dernier.
func TestBuildFromFile_ChunkLayout(t *testing.T) {
	tests := []struct {
		name         string
		dataSize     int
		chunkSize    uint32
		wantChunks   int
		wantLastSize uint32
	}{
		{
			name: "fichier vide",
			dataSize: 0, chunkSize: 1024,
			wantChunks: 0, wantLastSize: 0,
		},
		{
			name: "chunk partiel",
			dataSize: 500, chunkSize: 1024,
			wantChunks: 1, wantLastSize: 500,
		},
		{
			name: "un chunk exact",
			dataSize: 1024, chunkSize: 1024,
			wantChunks: 1, wantLastSize: 1024,
		},
		{
			name: "deux chunks exacts",
			dataSize: 2048, chunkSize: 1024,
			wantChunks: 2, wantLastSize: 1024,
		},
		{
			name: "deux chunks dont dernier partiel",
			dataSize: 1536, chunkSize: 1024,
			wantChunks: 2, wantLastSize: 512,
		},
		{
			name: "trois chunks",
			dataSize: 3000, chunkSize: 1024,
			wantChunks: 3, wantLastSize: 3000 - 2*1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := bytes.Repeat([]byte{0xAA}, tt.dataSize)
			path := writeTempFile(t, data)
			privKey := generateKey(t)

			m, err := buildFromFile(path, privKey, tt.chunkSize)
			if err != nil {
				t.Fatalf("buildFromFile: %v", err)
			}

			if len(m.Chunks) != tt.wantChunks {
				t.Errorf("got %d chunks, want %d", len(m.Chunks), tt.wantChunks)
			}
			if tt.wantChunks > 0 {
				last := m.Chunks[len(m.Chunks)-1]
				if last.Size != tt.wantLastSize {
					t.Errorf("last chunk size = %d, want %d", last.Size, tt.wantLastSize)
				}
			}
		})
	}
}

// TestBuildFromFile_ChunkOffsets vérifie que chaque chunk a le bon index et le bon offset.
func TestBuildFromFile_ChunkOffsets(t *testing.T) {
	const chunkSize = uint32(1024)
	data := bytes.Repeat([]byte{0xBB}, int(3*chunkSize+256))
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, err := buildFromFile(path, privKey, chunkSize)
	if err != nil {
		t.Fatalf("buildFromFile: %v", err)
	}

	for i, c := range m.Chunks {
		if c.Index != uint32(i) {
			t.Errorf("chunk[%d].Index = %d, want %d", i, c.Index, i)
		}
		wantOffset := uint64(i) * uint64(chunkSize)
		if c.Offset != wantOffset {
			t.Errorf("chunk[%d].Offset = %d, want %d", i, c.Offset, wantOffset)
		}
	}
}

// TestBuildFromFile_GlobalHash vérifie que Content.SHA512 est le SHA3-512 du fichier entier.
func TestBuildFromFile_GlobalHash(t *testing.T) {
	data := bytes.Repeat([]byte{0xCC}, 3000)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, err := buildFromFile(path, privKey, 1024)
	if err != nil {
		t.Fatalf("buildFromFile: %v", err)
	}

	expected := sha3.Sum512(data)
	if m.Content.SHA512 != expected {
		t.Error("Content.SHA512 ne correspond pas au SHA3-512 du fichier entier")
	}
}

// TestBuildFromFile_PerChunkHashes vérifie que chaque ChunkInfo.Hash correspond au SHA3-512 du chunk.
func TestBuildFromFile_PerChunkHashes(t *testing.T) {
	const chunkSize = 1024
	// Chaque chunk a un contenu distinct pour détecter toute inversion
	chunk0 := bytes.Repeat([]byte{0x11}, chunkSize)
	chunk1 := bytes.Repeat([]byte{0x22}, chunkSize)
	chunk2 := bytes.Repeat([]byte{0x33}, 512) // dernier chunk partiel
	data := append(append(chunk0, chunk1...), chunk2...)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, err := buildFromFile(path, privKey, chunkSize)
	if err != nil {
		t.Fatalf("buildFromFile: %v", err)
	}

	expected := [][64]byte{
		sha3.Sum512(chunk0),
		sha3.Sum512(chunk1),
		sha3.Sum512(chunk2),
	}
	for i, c := range m.Chunks {
		if c.Hash != expected[i] {
			t.Errorf("chunk[%d] hash mismatch", i)
		}
	}
}

// TestBuildFromFile_SignatureValid vérifie que le MFT construit a une signature valide.
func TestBuildFromFile_SignatureValid(t *testing.T) {
	data := bytes.Repeat([]byte{0x01}, 2048)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, err := buildFromFile(path, privKey, 1024)
	if err != nil {
		t.Fatalf("buildFromFile: %v", err)
	}

	if err := m.Verify(); err != nil {
		t.Errorf("Verify() = %v, want nil", err)
	}
}

// TestBuildFromFile_FileNotFound vérifie que l'erreur est remontée si le fichier n'existe pas.
func TestBuildFromFile_FileNotFound(t *testing.T) {
	privKey := generateKey(t)
	_, err := BuildFromFile("/nonexistent/path/file.bin", privKey)
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

// ===== ReadChunk =====

// TestReadChunk_CorrectData vérifie que les données lues correspondent exactement au fichier source.
func TestReadChunk_CorrectData(t *testing.T) {
	const chunkSize = 1024
	chunk0 := bytes.Repeat([]byte{0x11}, chunkSize)
	chunk1 := bytes.Repeat([]byte{0x22}, 512) // dernier chunk partiel
	data := append(chunk0, chunk1...)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, err := buildFromFile(path, privKey, chunkSize)
	if err != nil {
		t.Fatalf("buildFromFile: %v", err)
	}

	got0, err := m.ReadChunk(path, 0)
	if err != nil {
		t.Fatalf("ReadChunk(0): %v", err)
	}
	if !bytes.Equal(got0, chunk0) {
		t.Error("chunk 0 : données incorrectes")
	}

	got1, err := m.ReadChunk(path, 1)
	if err != nil {
		t.Fatalf("ReadChunk(1): %v", err)
	}
	if !bytes.Equal(got1, chunk1) {
		t.Error("chunk 1 : données incorrectes")
	}
}

// TestReadChunk_HashMismatch vérifie qu'une corruption du fichier source est détectée.
func TestReadChunk_HashMismatch(t *testing.T) {
	data := bytes.Repeat([]byte{0x42}, 2048)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, err := buildFromFile(path, privKey, 1024)
	if err != nil {
		t.Fatalf("buildFromFile: %v", err)
	}

	// Corrompre le premier octet du fichier
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteAt([]byte{0xFF}, 0)
	f.Close()

	_, err = m.ReadChunk(path, 0)
	if err == nil {
		t.Error("expected hash mismatch error, got nil")
	}
}

// TestReadChunk_IndexOutOfRange vérifie les erreurs sur des index invalides.
func TestReadChunk_IndexOutOfRange(t *testing.T) {
	data := bytes.Repeat([]byte{0x01}, 512)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, _ := buildFromFile(path, privKey, 1024)

	for _, idx := range []int{-1, 1, 100} {
		_, err := m.ReadChunk(path, idx)
		if err == nil {
			t.Errorf("ReadChunk(%d) : attendu une erreur, got nil", idx)
		}
	}
}

// TestReadChunk_FileNotFound vérifie l'erreur quand le fichier source est absent.
func TestReadChunk_FileNotFound(t *testing.T) {
	data := bytes.Repeat([]byte{0x01}, 512)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, _ := buildFromFile(path, privKey, 1024)

	_, err := m.ReadChunk("/nonexistent/path/file.bin", 0)
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

// ===== VerifyFileHash =====

// TestVerifyFileHash vérifie les trois cas : OK, taille différente, contenu différent.
func TestVerifyFileHash(t *testing.T) {
	data := bytes.Repeat([]byte{0x55}, 3000)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, err := buildFromFile(path, privKey, 1024)
	if err != nil {
		t.Fatalf("buildFromFile: %v", err)
	}

	t.Run("hash valide", func(t *testing.T) {
		if err := m.VerifyFileHash(path); err != nil {
			t.Errorf("VerifyFileHash: %v", err)
		}
	})

	t.Run("taille différente", func(t *testing.T) {
		// Fichier plus court → size mismatch
		shortPath := writeTempFile(t, data[:1000])
		if err := m.VerifyFileHash(shortPath); err == nil {
			t.Error("expected size mismatch error, got nil")
		}
	})

	t.Run("contenu différent même taille", func(t *testing.T) {
		differentPath := writeTempFile(t, bytes.Repeat([]byte{0x77}, 3000))
		if err := m.VerifyFileHash(differentPath); err == nil {
			t.Error("expected hash mismatch error, got nil")
		}
	})
}

// ===== Round-trip serialisation =====

// TestRoundTrip_ChunksPreserved vérifie que WriteBinary + ReadBinary conserve exactement les chunks.
func TestRoundTrip_ChunksPreserved(t *testing.T) {
	data := bytes.Repeat([]byte{0x99}, 3*1024)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	original, err := buildFromFile(path, privKey, 1024)
	if err != nil {
		t.Fatalf("buildFromFile: %v", err)
	}

	var buf bytes.Buffer
	if err := original.WriteBinary(&buf); err != nil {
		t.Fatalf("WriteBinary: %v", err)
	}

	restored := &MFT{}
	if err := restored.ReadBinary(&buf); err != nil {
		t.Fatalf("ReadBinary: %v", err)
	}

	if len(restored.Chunks) != len(original.Chunks) {
		t.Fatalf("got %d chunks, want %d", len(restored.Chunks), len(original.Chunks))
	}
	for i, c := range restored.Chunks {
		orig := original.Chunks[i]
		if c != orig {
			t.Errorf("chunk[%d] mismatch:\n  got  %+v\n  want %+v", i, c, orig)
		}
	}
}

// TestRoundTrip_SignatureVerifiesAfterRestore vérifie que la signature reste valide après désérialisation.
func TestRoundTrip_SignatureVerifiesAfterRestore(t *testing.T) {
	data := bytes.Repeat([]byte{0xAB}, 2048)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	original, err := buildFromFile(path, privKey, 1024)
	if err != nil {
		t.Fatalf("buildFromFile: %v", err)
	}

	var buf bytes.Buffer
	if err := original.WriteBinary(&buf); err != nil {
		t.Fatalf("WriteBinary: %v", err)
	}

	restored := &MFT{}
	if err := restored.ReadBinary(&buf); err != nil {
		t.Fatalf("ReadBinary: %v", err)
	}

	if err := restored.Verify(); err != nil {
		t.Errorf("Verify() après round-trip = %v, want nil", err)
	}
}
