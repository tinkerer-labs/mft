// Package mft
package mft

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// ===== CONSTANTES =====
const (
	MagicMFT       = "MFT1"
	VersionMFT     = 0x01
	MaxTitleLen    = 512 // Très généreux pour release names complets
	MaxMimeLen     = 32  // "application/octet-stream" etc.
	MaxTagLen      = 64  // Tags flexibles
	MaxTags        = 255
	MaxQualityLen  = 16 // "2160p", "4K", etc.
	MaxCodecLen    = 16 // "x265", "H264", etc.
	MaxAudioLen    = 24 // "DTS-HD MA 5.1", "AAC 2.0"
	MaxLanguageLen = 32 // "VOSTFR", "FRENCH", "MULTI"
	MaxSourceLen   = 16 // "WEB-DL", "BluRay", etc.
	MaxGroupLen    = 32 // "THESYNDiCATE", "SUXXORS"

	// Champs métadonnées étendues
	MaxCreatorLen   = 64 // Auteur, Artiste, Développeur, Studio, Réalisateur
	MaxPublisherLen = 48 // Éditeur, Label, Publisher, Network
	MaxGenreLen     = 32 // Genre du contenu
	MaxSeasonLen    = 8  // "S01", "Season 1"
	MaxEpisodeLen   = 8  // "E01", "01-12"
	MaxPlatformLen  = 24 // "Windows", "PlayStation 5", "Switch"
	MaxYearLen      = 4  // "2025"
	MaxDurationLen  = 12 // "2h30m", "142 min"

	ChunkDefault = 1 << 20
)

// Status flags pour Header.Flags
const (
	FlagSafe       = uint8(0)
	FlagSuspicious = uint8(1)
	FlagMalware    = uint8(2)
)

// Catégories de contenu
const (
	CategoryUnknown     = 0
	CategoryMovie       = 1  // Films
	CategoryTVShow      = 2  // Séries TV
	CategoryAnime       = 3  // Anime
	CategoryDocumentary = 4  // Documentaires
	CategorySport       = 5  // Sport
	CategoryMusic       = 6  // Musique
	CategoryAudiobook   = 7  // Livres audio
	CategoryEbook       = 8  // Livres électroniques
	CategoryComic       = 9  // Comics/Manga/BD
	CategoryGame        = 10 // Jeux vidéo
	CategorySoftware    = 11 // Applications/Logiciels
	CategoryAdult       = 12 // Contenu adulte
	CategoryKaraoke     = 13 // Karaoké
	CategoryShow        = 14 // Spectacles (théâtre, comédie, opéra)
	CategoryMusicVideo  = 15 // Clips musicaux
	Category3DModel     = 16 // Modèles 3D
	CategoryCourse      = 17 // Cours/Formations
	CategoryMagazine    = 18 // Magazines/Journaux
	CategoryOther       = 255
)

// ===== STRUCTURES BINAIRES =====

// Header: 48 bytes (fixe)
type Header struct {
	Magic       [4]byte  // "MFT1"
	Version     uint8    // 0x01
	ContentLen  [3]byte  // uint24 little-endian
	AnalysisLen [3]byte  // uint24 little-endian
	UploaderLen [3]byte  // uint24 little-endian
	PreviewLen  [3]byte  // uint24 little-endian
	ChunkLen    [3]byte  // uint24 little-endian
	Flags       uint8    // bit0=safe, bit1=suspicious, bit2=malware
	Reserved    [27]byte
}

// Content: taille variable selon padding
type Content struct {
	SHA512 [64]byte  // Hash du fichier réel
	Size   uint64    // Taille en bytes
	Title  [512]byte // Titre principal (sans métadonnées techniques)
	Mime   [32]byte  // "application/octet-stream\0"

	// Type de contenu
	Category uint8 // CategoryMovie, CategoryTVShow, etc.

	// Métadonnées techniques de release
	Quality  [16]byte // "1080p", "2160p", "4K", etc.
	Codec    [16]byte // "x265", "x264", "H264", "H265"
	Audio    [24]byte // "AAC", "DTS-HD MA 5.1", "FLAC"
	Language [32]byte // "VOSTFR", "FRENCH", "MULTI", etc.
	Source   [16]byte // "WEB-DL", "BluRay", "HDTV", "WEBRip"
	Group    [32]byte // Release group: "NOTAG", "PiCKLES", etc.

	// Métadonnées étendues (usage dépend de Category)
	Creator   [64]byte // Auteur, Artiste, Réalisateur, Développeur, Studio
	Publisher [48]byte // Éditeur, Label, Publisher, Network, Distributeur
	Genre     [32]byte // Genre: "Action", "RPG", "Romance", "Sci-Fi"
	Season    [8]byte  // "S01", "Season 1" (séries/anime)
	Episode   [8]byte  // "E01", "01-12", "OVA" (séries/anime)
	Platform  [24]byte // "Windows", "PS5", "Switch", "Android" (jeux/software)
	Year      [4]byte  // "2025" (année de sortie)
	Duration  [12]byte // "2h30m", "142min", "3:45:12" (vidéos/audio)

	TagsCount uint8   // Nombre de tags
	Reserved  [2]byte // Ajusté pour alignement

	ChunkSize uint32
}

// Analysis: taille variable selon padding
type Analysis struct {
	Timestamp         uint64   // Unix timestamp
	AVEngine          [32]byte // "Microsoft Defender\0" (augmenté pour noms longs)
	AVStatus          uint8    // 0=safe, 1=suspicious, 2=malware
	YaraHits          uint8    // Nombre de règles YARA matchées
	RiskScore         uint8    // 0-100
	AnalyzerImageHash [32]byte // SHA512 hash de l'image Docker d'analyse (pour vérification)
	AnalyzerVersion   [16]byte // Version de l'image (ex: "1.0.0\0")
	Reserved          [12]byte // Espace réservé pour extensions futures
}

// UploaderInfo: variable, répété pour chaque uploader
type UploaderInfo struct {
	PubKey     [32]byte // Ed25519 pubkey
	MaxBW      uint32   // bytes/sec (0 = unlimited)
	RatioLimit uint16   // 100 = 1.0x, 0 = unlimited
	MaxPeers   uint16   // Nombre peers simultanés
	QuotaMonth uint64   // bytes/month (0 = unlimited)
	Signature  [64]byte // Ed25519 signature de cet uploader
}

// ChunkInfo:
type ChunkInfo struct {
	Index  uint32
	Offset uint64
	Size   uint32
	Hash   [64]byte
}

// ===== STRUCTURE COMPLÈTE MFT =====

type MFT struct {
	// Structures immuables
	Header   Header
	Content  Content
	Analysis Analysis

	// Sections variables
	Uploaders []UploaderInfo // 1 à N uploaders
	Author    [32]byte       // Ed25519 pubkey du créateur
	Preview   []byte         // Données preview compressées
	Tags      []string       // Liste des tags

	// Signature finale (sur tout le reste)
	Signature [64]byte

	// Cache du hash du .mft lui-même (identifiant content-addressed)
	mftHash         [64]byte
	mftHashComputed bool

	// Chunks
	Chunks []ChunkInfo
}

// ===== FONCTIONS UTILITAIRES =====

func uint24ToBytes(val uint32) [3]byte {
	if val > 0xFFFFFF {
		val = 0xFFFFFF
	}
	return [3]byte{byte(val), byte(val >> 8), byte(val >> 16)}
}

func bytesToUint24(b [3]byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
}

func truncateNullTerminated(src []byte, maxLen int) []byte {
	if len(src) > maxLen {
		src = src[:maxLen]
	}
	for i, v := range src {
		if v == 0 {
			return src[:i]
		}
	}
	return src
}

// ===== SÉRIALISATION =====

// serializeWithoutSignature écrit le .mft en binaire (SANS signature)
func (m *MFT) serializeWithoutSignature() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Préparer uploaders et tags
	uploadersBuf := m.serializeUploaders()
	tagsBuf := m.serializeTags()

	// Calculer les lengths (utiliser binary.Size pour les tailles réelles)
	contentLen := uint32(binary.Size(m.Content))
	analysisLen := uint32(binary.Size(m.Analysis))
	uploaderLen := uint32(uploadersBuf.Len())
	previewLen := uint32(len(m.Preview))
	chunkLen := uint32(len(m.Chunks) * binary.Size(ChunkInfo{}))

	// Écrire header avec les lengths
	if err := m.writeHeaderWithLengths(buf, contentLen, analysisLen, uploaderLen, previewLen, chunkLen); err != nil {
		return nil, err
	}

	// Écrire sections
	sections := [][]byte{
		serializeStruct(m.Content),
		serializeStruct(m.Analysis),
		m.serializeChunks(),
		uploadersBuf.Bytes(),
		m.Author[:],
		m.Preview,
		tagsBuf.Bytes(),
	}

	for _, section := range sections {
		if _, err := buf.Write(section); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// writeHeaderWithLengths écrit le header avec les lengths calculés
func (m *MFT) writeHeaderWithLengths(buf *bytes.Buffer, contentLen, analysisLen, uploaderLen, previewLen, chunkLen uint32) error {
	buf.Write(m.Header.Magic[:])
	buf.WriteByte(m.Header.Version)

	contentBytes := uint24ToBytes(contentLen)
	buf.Write(contentBytes[:])

	analysisBytes := uint24ToBytes(analysisLen)
	buf.Write(analysisBytes[:])

	uploaderBytes := uint24ToBytes(uploaderLen)
	buf.Write(uploaderBytes[:])

	previewBytes := uint24ToBytes(previewLen)
	buf.Write(previewBytes[:])

	chunksBytes := uint24ToBytes(chunkLen)
	buf.Write(chunksBytes[:])

	buf.WriteByte(m.Header.Flags)
	buf.Write(m.Header.Reserved[:])

	return nil
}

// serializeStruct sérialise n'importe quelle struct en little-endian
func serializeStruct(v any) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, v)
	return buf.Bytes()
}

// serializeUploaders retourne la section Uploaders
func (m *MFT) serializeUploaders() *bytes.Buffer {
	buf := new(bytes.Buffer)
	for _, u := range m.Uploaders {
		binary.Write(buf, binary.LittleEndian, u)
	}
	return buf
}

// serializeChunks retourne la section Chunks
func (m *MFT) serializeChunks() []byte {
	buf := new(bytes.Buffer)
	for _, c := range m.Chunks {
		binary.Write(buf, binary.LittleEndian, c)
	}
	return buf.Bytes()
}

// serializeTags retourne la section Tags (nul-séparées)
func (m *MFT) serializeTags() *bytes.Buffer {
	buf := new(bytes.Buffer)
	for _, tag := range m.Tags {
		if len(tag) > MaxTagLen {
			tag = tag[:MaxTagLen]
		}
		buf.WriteString(tag)
		buf.WriteByte(0)
	}
	return buf
}

// WriteBinary écrit le .mft complet (avec signature) dans un writer
func (m *MFT) WriteBinary(w io.Writer) error {
	if m.Signature == [64]byte{} {
		return errors.New("mft not signed")
	}

	data, err := m.serializeWithoutSignature()
	if err != nil {
		return err
	}

	if _, err := w.Write(data); err != nil {
		return err
	}
	if _, err := w.Write(m.Signature[:]); err != nil {
		return err
	}

	return nil
}

// ===== DÉSÉRIALISATION =====

// ReadBinary lit un .mft binaire depuis un reader
func (m *MFT) ReadBinary(r io.Reader) error {
	allData, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	// Vérifier taille minimale
	minSize := binary.Size(Header{}) + 32 + 64 // Header + Author + Signature
	if len(allData) < minSize {
		return errors.New("mft too small")
	}

	offset := 0

	// 1. Magic + Version
	if string(allData[offset:offset+4]) != MagicMFT {
		return errors.New("invalid magic")
	}
	copy(m.Header.Magic[:], allData[offset:offset+4])
	offset += 4

	if allData[offset] != VersionMFT {
		return errors.New("unsupported version")
	}
	m.Header.Version = allData[offset]
	offset += 1

	// 2. Lire les 3 lengths (uint24)
	copy(m.Header.ContentLen[:], allData[offset:offset+3])
	contentLen := bytesToUint24([3]byte{allData[offset], allData[offset+1], allData[offset+2]})
	offset += 3

	copy(m.Header.AnalysisLen[:], allData[offset:offset+3])
	analysisLen := bytesToUint24([3]byte{allData[offset], allData[offset+1], allData[offset+2]})
	offset += 3

	copy(m.Header.UploaderLen[:], allData[offset:offset+3])
	uploaderLen := bytesToUint24([3]byte{allData[offset], allData[offset+1], allData[offset+2]})
	offset += 3

	copy(m.Header.PreviewLen[:], allData[offset:offset+3])
	previewLen := bytesToUint24([3]byte{allData[offset], allData[offset+1], allData[offset+2]})
	offset += 3

	copy(m.Header.ChunkLen[:], allData[offset:offset+3])
	chunkLen := bytesToUint24([3]byte{allData[offset], allData[offset+1], allData[offset+2]})
	offset += 3

	// 3. Flags + Reserved
	m.Header.Flags = allData[offset]
	offset += 1
	reservedSize := len(m.Header.Reserved)
	copy(m.Header.Reserved[:], allData[offset:offset+reservedSize])
	offset += reservedSize

	// 4. Content
	if offset+int(contentLen) > len(allData) {
		return errors.New("incomplete content section")
	}
	if err := m.parseContent(allData[offset : offset+int(contentLen)]); err != nil {
		return err
	}
	offset += int(contentLen)

	// 5. Analysis
	if offset+int(analysisLen) > len(allData) {
		return errors.New("incomplete analysis section")
	}
	if err := m.parseAnalysis(allData[offset : offset+int(analysisLen)]); err != nil {
		return err
	}
	offset += int(analysisLen)

	// 6. Chunks
	if offset+int(chunkLen) > len(allData) {
		return errors.New("incomplete chunks section")
	}
	if err := m.parseChunks(allData[offset : offset+int(chunkLen)]); err != nil {
		return err
	}
	offset += int(chunkLen)

	// 7. Uploaders
	if offset+int(uploaderLen) > len(allData) {
		return errors.New("incomplete uploaders section")
	}
	if err := m.parseUploaders(allData[offset : offset+int(uploaderLen)]); err != nil {
		return err
	}
	offset += int(uploaderLen)

	// 8. Author (32 bytes)
	if offset+32 > len(allData) {
		return errors.New("incomplete author section")
	}
	copy(m.Author[:], allData[offset:offset+32])
	offset += 32

	// 9. Preview
	if offset+int(previewLen) > len(allData) {
		return errors.New("incomplete preview section")
	}
	m.Preview = make([]byte, previewLen)
	copy(m.Preview, allData[offset:offset+int(previewLen)])
	offset += int(previewLen)

	// 10. Tags + Signature
	remaining := allData[offset:]
	if len(remaining) < 64 {
		return fmt.Errorf("mft too short for signature: need 64 bytes, have %d", len(remaining))
	}

	tagData := remaining[:len(remaining)-64]
	copy(m.Signature[:], remaining[len(remaining)-64:])

	// Parser tags
	if err := m.parseTags(tagData); err != nil {
		return err
	}

	return nil
}

// parseContent lit la section Content
func (m *MFT) parseContent(data []byte) error {
	expectedSize := binary.Size(Content{})
	if len(data) != expectedSize {
		return fmt.Errorf("content section must be %d bytes, got %d", expectedSize, len(data))
	}

	buf := bytes.NewReader(data)
	return binary.Read(buf, binary.LittleEndian, &m.Content)
}

// parseAnalysis lit la section Analysis
func (m *MFT) parseAnalysis(data []byte) error {
	expectedSize := binary.Size(Analysis{})
	if len(data) != expectedSize {
		return fmt.Errorf("analysis section must be %d bytes, got %d", expectedSize, len(data))
	}

	buf := bytes.NewReader(data)
	return binary.Read(buf, binary.LittleEndian, &m.Analysis)
}

// parseUploaders lit la section Uploaders (variable)
func (m *MFT) parseUploaders(data []byte) error {
	m.Uploaders = []UploaderInfo{}

	if len(data) == 0 {
		return nil // Pas d'uploaders
	}

	uploaderSize := binary.Size(UploaderInfo{})
	if len(data)%uploaderSize != 0 {
		return errors.New("uploaders section size mismatch")
	}

	buf := bytes.NewReader(data)
	for buf.Len() >= uploaderSize {
		var u UploaderInfo
		if err := binary.Read(buf, binary.LittleEndian, &u); err != nil {
			return err
		}
		m.Uploaders = append(m.Uploaders, u)
	}

	return nil
}

// parseChunks lit la section Chunks (tableau de ChunkInfo)
func (m *MFT) parseChunks(data []byte) error {
	m.Chunks = []ChunkInfo{}
	if len(data) == 0 {
		return nil
	}
	chunkSize := binary.Size(ChunkInfo{})
	if len(data)%chunkSize != 0 {
		return errors.New("chunks section size mismatch")
	}
	buf := bytes.NewReader(data)
	for buf.Len() >= chunkSize {
		var c ChunkInfo
		if err := binary.Read(buf, binary.LittleEndian, &c); err != nil {
			return err
		}
		m.Chunks = append(m.Chunks, c)
	}
	return nil
}

// parseTags parse la section tags (nul-séparées)
func (m *MFT) parseTags(data []byte) error {
	m.Tags = []string{}
	for _, part := range bytes.Split(data, []byte{0}) {
		tag := string(part)
		if tag != "" && len(tag) <= MaxTagLen {
			m.Tags = append(m.Tags, tag)
		}
	}
	return nil
}

// ===== CONSTRUCTION =====

// BuildFromFile construit un MFT depuis un fichier source avec les chunks par défaut (1MB).
// Il calcule le hash SHA3-512 global et par chunk en un seul passage, puis signe le tout.
func BuildFromFile(path string, privKey ed25519.PrivateKey) (*MFT, error) {
	return buildFromFile(path, privKey, ChunkDefault)
}

// buildFromFile est l'implémentation interne — chunkSize configurable pour les tests.
func buildFromFile(path string, privKey ed25519.PrivateKey, chunkSize uint32) (*MFT, error) {
	if chunkSize == 0 {
		chunkSize = ChunkDefault
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	m := &MFT{}
	copy(m.Header.Magic[:], MagicMFT)
	m.Header.Version = VersionMFT
	m.Content.Size = uint64(stat.Size())
	m.Content.ChunkSize = chunkSize

	// Author = clé publique du signataire
	pubKey := privKey.Public().(ed25519.PublicKey)
	copy(m.Author[:], pubKey)

	// Lecture en un seul passage : hash global + hash par chunk.
	// Chaque octet est lu une seule fois — O(1) en RAM quelle que soit la taille du fichier.
	globalHasher := sha3.New512()
	buf := make([]byte, chunkSize)
	var idx uint32
	var offset uint64

	for {
		n, err := io.ReadFull(file, buf)
		if n > 0 {
			data := buf[:n]
			globalHasher.Write(data)
			chunkHash := sha3.Sum512(data)
			m.Chunks = append(m.Chunks, ChunkInfo{
				Index:  idx,
				Offset: offset,
				Size:   uint32(n),
				Hash:   chunkHash,
			})
			idx++
			offset += uint64(n)
		}
		// io.ErrUnexpectedEOF = dernier chunk partiel (n < chunkSize)
		// io.EOF             = fichier vide ou chunk exact en fin de fichier
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read chunk %d: %w", idx, err)
		}
	}

	copy(m.Content.SHA512[:], globalHasher.Sum(nil))

	if err := m.Sign(privKey); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return m, nil
}

// ReadChunk lit le chunk d'index donné depuis le fichier source et vérifie son hash SHA3-512.
// La lecture est directe (seek + read) — le fichier source n'est jamais copié intégralement.
func (m *MFT) ReadChunk(sourcePath string, index int) ([]byte, error) {
	if index < 0 || index >= len(m.Chunks) {
		return nil, fmt.Errorf("chunk index %d out of range [0, %d)", index, len(m.Chunks))
	}

	chunk := m.Chunks[index]

	file, err := os.Open(sourcePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if _, err := file.Seek(int64(chunk.Offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek to chunk %d: %w", index, err)
	}

	data := make([]byte, chunk.Size)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, fmt.Errorf("read chunk %d: %w", index, err)
	}

	// Vérification d'intégrité : le hash doit correspondre exactement
	hash := sha3.Sum512(data)
	if hash != chunk.Hash {
		return nil, fmt.Errorf("chunk %d hash mismatch: data is corrupted", index)
	}

	return data, nil
}

// ===== SIGNATURE & VÉRIFICATION =====

// Sign signe le .mft avec la clé privée de l'auteur
func (m *MFT) Sign(privKey ed25519.PrivateKey) error {
	data, err := m.serializeWithoutSignature()
	if err != nil {
		return err
	}

	sig := ed25519.Sign(privKey, data)
	if len(sig) != 64 {
		return errors.New("invalid signature length")
	}

	copy(m.Signature[:], sig)
	m.mftHashComputed = false // Invalide le cache

	return nil
}

// Verify vérifie la signature du .mft
func (m *MFT) Verify() error {
	if m.Signature == [64]byte{} {
		return errors.New("mft not signed")
	}

	data, err := m.serializeWithoutSignature()
	if err != nil {
		return err
	}

	pubKey := ed25519.PublicKey(m.Author[:])
	if !ed25519.Verify(pubKey, data, m.Signature[:]) {
		return errors.New("signature verification failed")
	}

	return nil
}

// ===== VÉRIFICATION DE FICHIER =====

// VerifyFileHash vérifie que le fichier réel correspond au hash du .mft
func (m *MFT) VerifyFileHash(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}
	if uint64(stat.Size()) != m.Content.Size {
		return errors.New("file size mismatch")
	}

	h := sha3.New512()
	if _, err := io.Copy(h, file); err != nil {
		return fmt.Errorf("hash file: %w", err)
	}

	var fileHash [64]byte
	copy(fileHash[:], h.Sum(nil))

	if fileHash != m.Content.SHA512 {
		return errors.New("file hash mismatch: file has been modified or corrupted")
	}

	return nil
}

// ===== CONTENT ADDRESSING =====

// ComputeMFTHash calcule le hash du .mft lui-même (identifiant content-addressed)
func (m *MFT) ComputeMFTHash() ([64]byte, error) {
	if m.mftHashComputed {
		return m.mftHash, nil
	}

	data, err := m.serializeWithoutSignature()
	if err != nil {
		return [64]byte{}, err
	}

	data = append(data, m.Signature[:]...)

	hash := sha3.Sum512(data)
	m.mftHash = hash
	m.mftHashComputed = true

	return hash, nil
}

// MFTFileName retourne le nom du fichier .mft basé sur son hash
func (m *MFT) MFTFileName() (string, error) {
	hash, err := m.ComputeMFTHash()
	if err != nil {
		return "", err
	}

	return hashToHex(hash[:]), nil
}

func hashToHex(hash []byte) string {
	return hex.EncodeToString(hash) + ".mft"
}

// ===== HELPERS =====

// SetTitle définit le titre (avec troncature auto)
func (m *MFT) SetTitle(title string) {
	if len(title) > MaxTitleLen-1 {
		title = title[:MaxTitleLen-1]
	}
	copy(m.Content.Title[:], title)
}

// GetTitle retourne le titre (nul-terminé)
func (m *MFT) GetTitle() string {
	return string(truncateNullTerminated(m.Content.Title[:], MaxTitleLen))
}

// SetMime définit le MIME type
func (m *MFT) SetMime(mime string) {
	if len(mime) > MaxMimeLen-1 {
		mime = mime[:MaxMimeLen-1]
	}
	copy(m.Content.Mime[:], mime)
}

// GetMime retourne le MIME type
func (m *MFT) GetMime() string {
	return string(truncateNullTerminated(m.Content.Mime[:], MaxMimeLen))
}

// SetStatusFlag définit le flag de status (FlagSafe, FlagSuspicious, FlagMalware)
func (m *MFT) SetStatusFlag(status uint8) {
	m.Header.Flags = status
}

// GetStatus retourne le statut lisible
func (m *MFT) GetStatus() string {
	switch m.Header.Flags {
	case FlagSafe:
		return "SAFE"
	case FlagSuspicious:
		return "SUSPICIOUS"
	case FlagMalware:
		return "MALWARE"
	default:
		return "UNKNOWN"
	}
}

// SetTimestamp définit le timestamp de l'analyse
func (m *MFT) SetTimestamp(t time.Time) {
	m.Analysis.Timestamp = uint64(t.Unix())
}

// GetTimestamp retourne le timestamp
func (m *MFT) GetTimestamp() time.Time {
	return time.Unix(int64(m.Analysis.Timestamp), 0)
}

// SetAVEngine définit le moteur AV utilisé
func (m *MFT) SetAVEngine(engine string) {
	if len(engine) > len(m.Analysis.AVEngine)-1 {
		engine = engine[:len(m.Analysis.AVEngine)-1]
	}
	copy(m.Analysis.AVEngine[:], engine)
}

// GetAVEngine retourne le moteur AV
func (m *MFT) GetAVEngine() string {
	return string(truncateNullTerminated(m.Analysis.AVEngine[:], len(m.Analysis.AVEngine)))
}

// ===== HELPERS MÉTADONNÉES RELEASE =====

// SetQuality définit la qualité (1080p, 2160p, 4K, etc.)
func (m *MFT) SetQuality(quality string) {
	if len(quality) > MaxQualityLen-1 {
		quality = quality[:MaxQualityLen-1]
	}
	copy(m.Content.Quality[:], quality)
}

// GetQuality retourne la qualité
func (m *MFT) GetQuality() string {
	return string(truncateNullTerminated(m.Content.Quality[:], MaxQualityLen))
}

// SetCodec définit le codec (x265, H264, etc.)
func (m *MFT) SetCodec(codec string) {
	if len(codec) > MaxCodecLen-1 {
		codec = codec[:MaxCodecLen-1]
	}
	copy(m.Content.Codec[:], codec)
}

// GetCodec retourne le codec
func (m *MFT) GetCodec() string {
	return string(truncateNullTerminated(m.Content.Codec[:], MaxCodecLen))
}

// SetAudio définit le codec audio (AAC, DTS, etc.)
func (m *MFT) SetAudio(audio string) {
	if len(audio) > MaxAudioLen-1 {
		audio = audio[:MaxAudioLen-1]
	}
	copy(m.Content.Audio[:], audio)
}

// GetAudio retourne le codec audio
func (m *MFT) GetAudio() string {
	return string(truncateNullTerminated(m.Content.Audio[:], MaxAudioLen))
}

// SetLanguage définit la langue (VOSTFR, FRENCH, etc.)
func (m *MFT) SetLanguage(language string) {
	if len(language) > MaxLanguageLen-1 {
		language = language[:MaxLanguageLen-1]
	}
	copy(m.Content.Language[:], language)
}

// GetLanguage retourne la langue
func (m *MFT) GetLanguage() string {
	return string(truncateNullTerminated(m.Content.Language[:], MaxLanguageLen))
}

// SetSource définit la source (WEB-DL, BluRay, etc.)
func (m *MFT) SetSource(source string) {
	if len(source) > MaxSourceLen-1 {
		source = source[:MaxSourceLen-1]
	}
	copy(m.Content.Source[:], source)
}

// GetSource retourne la source
func (m *MFT) GetSource() string {
	return string(truncateNullTerminated(m.Content.Source[:], MaxSourceLen))
}

// SetGroup définit le groupe de release
func (m *MFT) SetGroup(group string) {
	if len(group) > MaxGroupLen-1 {
		group = group[:MaxGroupLen-1]
	}
	copy(m.Content.Group[:], group)
}

// GetGroup retourne le groupe de release
func (m *MFT) GetGroup() string {
	return string(truncateNullTerminated(m.Content.Group[:], MaxGroupLen))
}

// ===== HELPERS MÉTADONNÉES ÉTENDUES =====

// SetCategory définit la catégorie de contenu
func (m *MFT) SetCategory(category uint8) {
	m.Content.Category = category
}

// GetCategory retourne la catégorie de contenu
func (m *MFT) GetCategory() uint8 {
	return m.Content.Category
}

// GetCategoryName retourne le nom lisible de la catégorie
func (m *MFT) GetCategoryName() string {
	switch m.Content.Category {
	case CategoryMovie:
		return "Movie"
	case CategoryTVShow:
		return "TV Show"
	case CategoryAnime:
		return "Anime"
	case CategoryDocumentary:
		return "Documentary"
	case CategorySport:
		return "Sport"
	case CategoryMusic:
		return "Music"
	case CategoryAudiobook:
		return "Audiobook"
	case CategoryEbook:
		return "eBook"
	case CategoryComic:
		return "Comic/Manga"
	case CategoryGame:
		return "Game"
	case CategorySoftware:
		return "Software"
	case CategoryAdult:
		return "Adult"
	case CategoryKaraoke:
		return "Karaoke"
	case CategoryShow:
		return "Show"
	case CategoryMusicVideo:
		return "Music Video"
	case Category3DModel:
		return "3D Model"
	case CategoryCourse:
		return "Course"
	case CategoryMagazine:
		return "Magazine"
	default:
		return "Unknown"
	}
}

// SetCreator définit le créateur (auteur, artiste, réalisateur, etc.)
func (m *MFT) SetCreator(creator string) {
	if len(creator) > MaxCreatorLen-1 {
		creator = creator[:MaxCreatorLen-1]
	}
	copy(m.Content.Creator[:], creator)
}

// GetCreator retourne le créateur
func (m *MFT) GetCreator() string {
	return string(truncateNullTerminated(m.Content.Creator[:], MaxCreatorLen))
}

// SetPublisher définit l'éditeur/publisher
func (m *MFT) SetPublisher(publisher string) {
	if len(publisher) > MaxPublisherLen-1 {
		publisher = publisher[:MaxPublisherLen-1]
	}
	copy(m.Content.Publisher[:], publisher)
}

// GetPublisher retourne l'éditeur
func (m *MFT) GetPublisher() string {
	return string(truncateNullTerminated(m.Content.Publisher[:], MaxPublisherLen))
}

// SetGenre définit le genre
func (m *MFT) SetGenre(genre string) {
	if len(genre) > MaxGenreLen-1 {
		genre = genre[:MaxGenreLen-1]
	}
	copy(m.Content.Genre[:], genre)
}

// GetGenre retourne le genre
func (m *MFT) GetGenre() string {
	return string(truncateNullTerminated(m.Content.Genre[:], MaxGenreLen))
}

// SetSeason définit la saison
func (m *MFT) SetSeason(season string) {
	if len(season) > MaxSeasonLen-1 {
		season = season[:MaxSeasonLen-1]
	}
	copy(m.Content.Season[:], season)
}

// GetSeason retourne la saison
func (m *MFT) GetSeason() string {
	return string(truncateNullTerminated(m.Content.Season[:], MaxSeasonLen))
}

// SetEpisode définit l'épisode
func (m *MFT) SetEpisode(episode string) {
	if len(episode) > MaxEpisodeLen-1 {
		episode = episode[:MaxEpisodeLen-1]
	}
	copy(m.Content.Episode[:], episode)
}

// GetEpisode retourne l'épisode
func (m *MFT) GetEpisode() string {
	return string(truncateNullTerminated(m.Content.Episode[:], MaxEpisodeLen))
}

// SetPlatform définit la plateforme
func (m *MFT) SetPlatform(platform string) {
	if len(platform) > MaxPlatformLen-1 {
		platform = platform[:MaxPlatformLen-1]
	}
	copy(m.Content.Platform[:], platform)
}

// GetPlatform retourne la plateforme
func (m *MFT) GetPlatform() string {
	return string(truncateNullTerminated(m.Content.Platform[:], MaxPlatformLen))
}

// SetYear définit l'année
func (m *MFT) SetYear(year string) {
	if len(year) > MaxYearLen {
		year = year[:MaxYearLen]
	}
	copy(m.Content.Year[:], year)
}

// GetYear retourne l'année
func (m *MFT) GetYear() string {
	return string(truncateNullTerminated(m.Content.Year[:], MaxYearLen))
}

// SetDuration définit la durée
func (m *MFT) SetDuration(duration string) {
	if len(duration) > MaxDurationLen-1 {
		duration = duration[:MaxDurationLen-1]
	}
	copy(m.Content.Duration[:], duration)
}

// GetDuration retourne la durée
func (m *MFT) GetDuration() string {
	return string(truncateNullTerminated(m.Content.Duration[:], MaxDurationLen))
}

// SetAnalyzerImageHash définit le hash SHA512 de l'image Docker utilisée pour l'analyse
func (m *MFT) SetAnalyzerImageHash(hash [32]byte) {
	m.Analysis.AnalyzerImageHash = hash
}

// SetAnalyzerImageHashFromHex définit le hash depuis une string hex
func (m *MFT) SetAnalyzerImageHashFromHex(hexHash string) error {
	b, err := hex.DecodeString(hexHash)
	if err != nil {
		return fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("hash must be 32 bytes, got %d", len(b))
	}
	copy(m.Analysis.AnalyzerImageHash[:], b)
	return nil
}

// GetAnalyzerImageHash retourne le hash de l'image Docker
func (m *MFT) GetAnalyzerImageHash() [32]byte {
	return m.Analysis.AnalyzerImageHash
}

// GetAnalyzerImageHashHex retourne le hash en format hex
func (m *MFT) GetAnalyzerImageHashHex() string {
	return fmt.Sprintf("%x", m.Analysis.AnalyzerImageHash)
}

// SetAnalyzerVersion définit la version de l'analyseur
func (m *MFT) SetAnalyzerVersion(version string) {
	if len(version) > 15 {
		version = version[:15]
	}
	copy(m.Analysis.AnalyzerVersion[:], version)
}

// GetAnalyzerVersion retourne la version de l'analyseur
func (m *MFT) GetAnalyzerVersion() string {
	return string(truncateNullTerminated(m.Analysis.AnalyzerVersion[:], 16))
}

// AddUploaderInfo ajoute un uploader avec ses limites
func (m *MFT) AddUploaderInfo(pubKey [32]byte, maxBW uint32, ratioLimit, maxPeers uint16, quotaMonth uint64) UploaderInfo {
	u := UploaderInfo{
		PubKey:     pubKey,
		MaxBW:      maxBW,
		RatioLimit: ratioLimit,
		MaxPeers:   maxPeers,
		QuotaMonth: quotaMonth,
	}
	m.Uploaders = append(m.Uploaders, u)
	return u
}

// SignUploaderInfo signe les données d'un uploader
func (u *UploaderInfo) Sign(privKey ed25519.PrivateKey) error {
	data := fmt.Sprintf("%x:%d:%d:%d:%d", u.PubKey, u.MaxBW, u.RatioLimit, u.MaxPeers, u.QuotaMonth)
	sig := ed25519.Sign(privKey, []byte(data))
	copy(u.Signature[:], sig)
	return nil
}

// VerifyUploaderSignature vérifie la signature d'un uploader
func (u *UploaderInfo) VerifySignature() bool {
	data := fmt.Sprintf("%x:%d:%d:%d:%d", u.PubKey, u.MaxBW, u.RatioLimit, u.MaxPeers, u.QuotaMonth)
	pubKey := ed25519.PublicKey(u.PubKey[:])
	return ed25519.Verify(pubKey, []byte(data), u.Signature[:])
}

// LoadMFT charge un fichier MFT depuis le disque
func LoadMFT(path string) (*MFT, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open MFT file: %w", err)
	}
	defer file.Close()

	mft := &MFT{}
	if err := mft.ReadBinary(file); err != nil {
		return nil, fmt.Errorf("failed to read MFT: %w", err)
	}

	return mft, nil
}

