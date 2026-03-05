package mft

// Tests pour : getters/setters, statuts, catégories, uploaders, content-addressing, LoadMFT,
// et les branches d'erreur non couvertes dans ReadBinary / WriteBinary / Verify.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ===== GETTERS / SETTERS STRING =====

// TestMetadataGetSet vérifie le round-trip Set→Get pour tous les champs string,
// et qu'une valeur trop longue ne fait pas planter (truncation silencieuse).
func TestMetadataGetSet(t *testing.T) {
	tests := []struct {
		name   string
		set    func(*MFT, string)
		get    func(*MFT) string
		maxLen int
	}{
		{"Title", (*MFT).SetTitle, (*MFT).GetTitle, MaxTitleLen},
		{"Mime", (*MFT).SetMime, (*MFT).GetMime, MaxMimeLen},
		{"Quality", (*MFT).SetQuality, (*MFT).GetQuality, MaxQualityLen},
		{"Codec", (*MFT).SetCodec, (*MFT).GetCodec, MaxCodecLen},
		{"Audio", (*MFT).SetAudio, (*MFT).GetAudio, MaxAudioLen},
		{"Language", (*MFT).SetLanguage, (*MFT).GetLanguage, MaxLanguageLen},
		{"Source", (*MFT).SetSource, (*MFT).GetSource, MaxSourceLen},
		{"Group", (*MFT).SetGroup, (*MFT).GetGroup, MaxGroupLen},
		{"Creator", (*MFT).SetCreator, (*MFT).GetCreator, MaxCreatorLen},
		{"Publisher", (*MFT).SetPublisher, (*MFT).GetPublisher, MaxPublisherLen},
		{"Genre", (*MFT).SetGenre, (*MFT).GetGenre, MaxGenreLen},
		{"Season", (*MFT).SetSeason, (*MFT).GetSeason, MaxSeasonLen},
		{"Episode", (*MFT).SetEpisode, (*MFT).GetEpisode, MaxEpisodeLen},
		{"Platform", (*MFT).SetPlatform, (*MFT).GetPlatform, MaxPlatformLen},
		{"Duration", (*MFT).SetDuration, (*MFT).GetDuration, MaxDurationLen},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MFT{}

			// Round-trip avec une valeur courte
			tt.set(m, "hello")
			if got := tt.get(m); got != "hello" {
				t.Errorf("round-trip: got %q, want %q", got, "hello")
			}

			// Vide → vide
			m2 := &MFT{}
			if got := tt.get(m2); got != "" {
				t.Errorf("empty: got %q, want \"\"", got)
			}

			// Valeur trop longue → pas de panic, résultat tronqué < maxLen
			m3 := &MFT{}
			long := strings.Repeat("x", tt.maxLen+10)
			tt.set(m3, long)
			got := tt.get(m3)
			if len(got) >= tt.maxLen {
				t.Errorf("truncation: got len=%d, want < %d", len(got), tt.maxLen)
			}
		})
	}
}

// TestSetGetYear cas spécial : Year est [4]byte sans null-terminator réservé.
func TestSetGetYear(t *testing.T) {
	m := &MFT{}

	m.SetYear("2025")
	if got := m.GetYear(); got != "2025" {
		t.Errorf("got %q, want %q", got, "2025")
	}

	// Trop long → tronqué à 4 chars
	m.SetYear("20256789")
	if got := m.GetYear(); got != "2025" {
		t.Errorf("truncation: got %q, want %q", got, "2025")
	}
}

// ===== SETAVENGINE / GETAVENGINE =====

func TestAVEngineGetSet(t *testing.T) {
	m := &MFT{}
	m.SetAVEngine("ClamAV")
	if got := m.GetAVEngine(); got != "ClamAV" {
		t.Errorf("got %q, want %q", got, "ClamAV")
	}
}

// ===== SETANALYZERVERSION / GETANALYZERVERSION =====

func TestAnalyzerVersionGetSet(t *testing.T) {
	m := &MFT{}
	m.SetAnalyzerVersion("1.2.3")
	if got := m.GetAnalyzerVersion(); got != "1.2.3" {
		t.Errorf("got %q, want %q", got, "1.2.3")
	}
}

// ===== TIMESTAMP =====

func TestTimestampRoundTrip(t *testing.T) {
	m := &MFT{}
	now := time.Unix(1700000000, 0) // timestamp fixe pour la reproductibilité
	m.SetTimestamp(now)
	got := m.GetTimestamp()
	if got.Unix() != now.Unix() {
		t.Errorf("timestamp round-trip: got %d, want %d", got.Unix(), now.Unix())
	}
}

// ===== ANALYZER IMAGE HASH =====

func TestSetAnalyzerImageHash(t *testing.T) {
	m := &MFT{}
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(i)
	}
	m.SetAnalyzerImageHash(hash)
	if m.GetAnalyzerImageHash() != hash {
		t.Error("GetAnalyzerImageHash mismatch")
	}
}

func TestSetAnalyzerImageHashFromHex(t *testing.T) {
	m := &MFT{}

	var original [32]byte
	for i := range original {
		original[i] = byte(i * 2)
	}
	hexStr := hex.EncodeToString(original[:])

	if err := m.SetAnalyzerImageHashFromHex(hexStr); err != nil {
		t.Fatalf("SetAnalyzerImageHashFromHex: %v", err)
	}
	if m.GetAnalyzerImageHash() != original {
		t.Error("hash mismatch after SetAnalyzerImageHashFromHex")
	}

	// Hex invalide
	if err := m.SetAnalyzerImageHashFromHex("notvalidhex!!"); err == nil {
		t.Error("expected error for invalid hex, got nil")
	}

	// Bonne longueur hex mais mauvaise taille en bytes (16 bytes au lieu de 32)
	shortHex := hex.EncodeToString(make([]byte, 16))
	if err := m.SetAnalyzerImageHashFromHex(shortHex); err == nil {
		t.Error("expected error for wrong size, got nil")
	}
}

func TestGetAnalyzerImageHashHex(t *testing.T) {
	m := &MFT{}
	var h [32]byte
	h[0] = 0xAB
	m.SetAnalyzerImageHash(h)
	hexStr := m.GetAnalyzerImageHashHex()
	if !strings.HasPrefix(hexStr, "ab") {
		t.Errorf("GetAnalyzerImageHashHex = %q, should start with \"ab\"", hexStr)
	}
}

// ===== STATUS FLAG =====

func TestGetStatus(t *testing.T) {
	tests := []struct {
		flag uint8
		want string
	}{
		{FlagSafe, "SAFE"},
		{FlagSuspicious, "SUSPICIOUS"},
		{FlagMalware, "MALWARE"},
		{99, "UNKNOWN"},
	}

	for _, tt := range tests {
		m := &MFT{}
		m.SetStatusFlag(tt.flag)
		if got := m.GetStatus(); got != tt.want {
			t.Errorf("flag=%d: got %q, want %q", tt.flag, got, tt.want)
		}
	}
}

// ===== CATÉGORIE =====

func TestSetGetCategory(t *testing.T) {
	m := &MFT{}
	m.SetCategory(CategoryMovie)
	if got := m.GetCategory(); got != CategoryMovie {
		t.Errorf("GetCategory = %d, want %d", got, CategoryMovie)
	}
}

func TestGetCategoryName(t *testing.T) {
	tests := []struct {
		cat  uint8
		want string
	}{
		{CategoryMovie, "Movie"},
		{CategoryTVShow, "TV Show"},
		{CategoryAnime, "Anime"},
		{CategoryDocumentary, "Documentary"},
		{CategorySport, "Sport"},
		{CategoryMusic, "Music"},
		{CategoryAudiobook, "Audiobook"},
		{CategoryEbook, "eBook"},
		{CategoryComic, "Comic/Manga"},
		{CategoryGame, "Game"},
		{CategorySoftware, "Software"},
		{CategoryAdult, "Adult"},
		{CategoryKaraoke, "Karaoke"},
		{CategoryShow, "Show"},
		{CategoryMusicVideo, "Music Video"},
		{Category3DModel, "3D Model"},
		{CategoryCourse, "Course"},
		{CategoryMagazine, "Magazine"},
		{CategoryUnknown, "Unknown"},
		{CategoryOther, "Unknown"},
	}

	for _, tt := range tests {
		m := &MFT{}
		m.SetCategory(tt.cat)
		if got := m.GetCategoryName(); got != tt.want {
			t.Errorf("category %d: got %q, want %q", tt.cat, got, tt.want)
		}
	}
}

// ===== UPLOADERS =====

func TestAddUploaderInfo(t *testing.T) {
	m := &MFT{}
	var pubKey [32]byte
	pubKey[0] = 0x42

	u := m.AddUploaderInfo(pubKey, 1024*1024, 150, 10, 5*1024*1024*1024)

	if len(m.Uploaders) != 1 {
		t.Fatalf("got %d uploaders, want 1", len(m.Uploaders))
	}
	if m.Uploaders[0].PubKey != pubKey {
		t.Error("PubKey mismatch")
	}
	if m.Uploaders[0].MaxBW != 1024*1024 {
		t.Error("MaxBW mismatch")
	}
	_ = u
}

func TestUploaderInfo_SignAndVerify(t *testing.T) {
	privKey := generateKey(t)

	var pub [32]byte
	copy(pub[:], privKey[32:]) // Ed25519 : les 32 derniers octets de privKey = pubKey

	u := &UploaderInfo{
		PubKey:     pub,
		MaxBW:      512 * 1024,
		RatioLimit: 100,
		MaxPeers:   5,
		QuotaMonth: 1 << 30,
	}

	if err := u.Sign(privKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !u.VerifySignature() {
		t.Error("VerifySignature() returned false for valid signature")
	}

	// Corrompre la signature → doit échouer
	u.Signature[0] ^= 0xFF
	if u.VerifySignature() {
		t.Error("VerifySignature() returned true for corrupted signature")
	}
}

// TestRoundTrip_WithUploaders vérifie que les uploaders survivent à la sérialisation.
func TestRoundTrip_WithUploaders(t *testing.T) {
	data := bytes.Repeat([]byte{0x01}, 512)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, err := buildFromFile(path, privKey, 256)
	if err != nil {
		t.Fatalf("buildFromFile: %v", err)
	}

	var pub [32]byte
	copy(pub[:], privKey[32:])
	m.AddUploaderInfo(pub, 1024, 100, 5, 0)

	// Re-signer après ajout de l'uploader
	if err := m.Sign(privKey); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	var buf bytes.Buffer
	if err := m.WriteBinary(&buf); err != nil {
		t.Fatalf("WriteBinary: %v", err)
	}

	restored := &MFT{}
	if err := restored.ReadBinary(&buf); err != nil {
		t.Fatalf("ReadBinary: %v", err)
	}

	if len(restored.Uploaders) != 1 {
		t.Fatalf("got %d uploaders, want 1", len(restored.Uploaders))
	}
	if restored.Uploaders[0].PubKey != pub {
		t.Error("uploader PubKey mismatch after round-trip")
	}
}

// ===== CONTENT ADDRESSING =====

func TestComputeMFTHash(t *testing.T) {
	data := bytes.Repeat([]byte{0x01}, 512)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, err := buildFromFile(path, privKey, 256)
	if err != nil {
		t.Fatalf("buildFromFile: %v", err)
	}

	hash1, err := m.ComputeMFTHash()
	if err != nil {
		t.Fatalf("ComputeMFTHash: %v", err)
	}
	if hash1 == [64]byte{} {
		t.Error("hash is all zeros")
	}

	// Deuxième appel : même résultat (cache)
	hash2, err := m.ComputeMFTHash()
	if err != nil {
		t.Fatalf("ComputeMFTHash (cached): %v", err)
	}
	if hash1 != hash2 {
		t.Error("hash changed between calls (cache broken)")
	}
}

func TestMFTFileName(t *testing.T) {
	data := bytes.Repeat([]byte{0x01}, 512)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, _ := buildFromFile(path, privKey, 256)

	name, err := m.MFTFileName()
	if err != nil {
		t.Fatalf("MFTFileName: %v", err)
	}
	if !strings.HasSuffix(name, ".mft") {
		t.Errorf("MFTFileName = %q, want *.mft suffix", name)
	}
	// Le nom doit être un hash hex (128 chars) + ".mft"
	if len(name) != 128+4 {
		t.Errorf("MFTFileName length = %d, want %d", len(name), 128+4)
	}
}

// ===== LOAD MFT =====

func TestLoadMFT(t *testing.T) {
	data := bytes.Repeat([]byte{0x42}, 512)
	srcPath := writeTempFile(t, data)
	privKey := generateKey(t)

	m, err := buildFromFile(srcPath, privKey, 256)
	if err != nil {
		t.Fatalf("buildFromFile: %v", err)
	}

	// Écrire sur disque
	mftPath := filepath.Join(t.TempDir(), "test.mft")
	f, err := os.Create(mftPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.WriteBinary(f); err != nil {
		f.Close()
		t.Fatalf("WriteBinary: %v", err)
	}
	f.Close()

	// Charger
	loaded, err := LoadMFT(mftPath)
	if err != nil {
		t.Fatalf("LoadMFT: %v", err)
	}
	if loaded.Content.Size != m.Content.Size {
		t.Errorf("Content.Size = %d, want %d", loaded.Content.Size, m.Content.Size)
	}
	if loaded.Content.SHA512 != m.Content.SHA512 {
		t.Error("Content.SHA512 mismatch after LoadMFT")
	}
}

func TestLoadMFT_FileNotFound(t *testing.T) {
	_, err := LoadMFT("/nonexistent/path/file.mft")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ===== BRANCHES D'ERREUR =====

// TestWriteBinary_NotSigned vérifie l'erreur quand le MFT n'est pas signé.
func TestWriteBinary_NotSigned(t *testing.T) {
	m := &MFT{}
	copy(m.Header.Magic[:], MagicMFT)
	m.Header.Version = VersionMFT

	var buf bytes.Buffer
	if err := m.WriteBinary(&buf); err == nil {
		t.Error("expected error for unsigned MFT, got nil")
	}
}

// TestVerify_NotSigned vérifie l'erreur quand la signature est vide.
func TestVerify_NotSigned(t *testing.T) {
	m := &MFT{}
	if err := m.Verify(); err == nil {
		t.Error("expected error for unsigned MFT, got nil")
	}
}

// TestVerify_InvalidSignature vérifie que la vérification échoue après corruption.
func TestVerify_InvalidSignature(t *testing.T) {
	data := bytes.Repeat([]byte{0x01}, 512)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, _ := buildFromFile(path, privKey, 256)

	// Corrompre la signature
	m.Signature[0] ^= 0xFF
	if err := m.Verify(); err == nil {
		t.Error("expected verification failure, got nil")
	}
}

// TestReadBinary_TooSmall vérifie l'erreur sur un fichier trop petit.
func TestReadBinary_TooSmall(t *testing.T) {
	m := &MFT{}
	r := bytes.NewReader([]byte{0x01, 0x02, 0x03})
	if err := m.ReadBinary(r); err == nil {
		t.Error("expected error for too-small input, got nil")
	}
}

// TestReadBinary_InvalidMagic vérifie l'erreur sur un magic invalide.
func TestReadBinary_InvalidMagic(t *testing.T) {
	// Construire un buffer de taille suffisante mais avec un mauvais magic
	buf := make([]byte, 200)
	copy(buf[:4], "XXXX") // mauvais magic

	m := &MFT{}
	if err := m.ReadBinary(bytes.NewReader(buf)); err == nil {
		t.Error("expected error for invalid magic, got nil")
	}
}

// TestUint24ToBytes_Overflow vérifie que les valeurs > 0xFFFFFF sont plafonnées.
func TestUint24ToBytes_Overflow(t *testing.T) {
	result := uint24ToBytes(0x1FFFFFF)
	back := bytesToUint24(result)
	if back != 0xFFFFFF {
		t.Errorf("overflow: got %d, want %d", back, 0xFFFFFF)
	}
}

// TestParseChunks_SizeMismatch vérifie l'erreur quand la section Chunks a une taille incorrecte.
func TestParseChunks_SizeMismatch(t *testing.T) {
	m := &MFT{}
	// 81 bytes n'est pas un multiple de 80 (taille d'un ChunkInfo)
	badData := make([]byte, 81)
	if err := m.parseChunks(badData); err == nil {
		t.Error("expected size mismatch error, got nil")
	}
}

// TestSerializeTags_LongTagTruncated vérifie que les tags trop longs sont tronqués à la sérialisation.
func TestSerializeTags_LongTagTruncated(t *testing.T) {
	m := &MFT{}
	m.Tags = []string{strings.Repeat("x", MaxTagLen+10)}

	buf := m.serializeTags()
	content := buf.Bytes()

	// Le tag sérialisé doit se terminer par 0x00 et faire <= MaxTagLen+1 octets
	tagBytes := bytes.TrimRight(content, "\x00")
	if len(tagBytes) > MaxTagLen {
		t.Errorf("serialized tag len = %d, want <= %d", len(tagBytes), MaxTagLen)
	}
}

// TestParseContent_WrongSize vérifie l'erreur quand la section Content a une taille inattendue.
func TestParseContent_WrongSize(t *testing.T) {
	m := &MFT{}
	if err := m.parseContent(make([]byte, 10)); err == nil {
		t.Error("expected error for wrong content size, got nil")
	}
}

// TestParseAnalysis_WrongSize vérifie l'erreur quand la section Analysis a une taille inattendue.
func TestParseAnalysis_WrongSize(t *testing.T) {
	m := &MFT{}
	if err := m.parseAnalysis(make([]byte, 10)); err == nil {
		t.Error("expected error for wrong analysis size, got nil")
	}
}

// failWriter est un io.Writer qui retourne toujours une erreur.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

// secondWriteFails réussit le premier Write, échoue à partir du deuxième.
type secondWriteFails struct{ count int }

func (w *secondWriteFails) Write(p []byte) (int, error) {
	w.count++
	if w.count > 1 {
		return 0, os.ErrClosed
	}
	return len(p), nil
}

// TestWriteBinary_WriteError vérifie que les erreurs d'écriture sont bien remontées.
func TestWriteBinary_WriteError(t *testing.T) {
	data := bytes.Repeat([]byte{0x01}, 512)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, err := buildFromFile(path, privKey, 256)
	if err != nil {
		t.Fatalf("buildFromFile: %v", err)
	}

	// Échec sur la première écriture (le corps du MFT)
	if err := m.WriteBinary(failWriter{}); err == nil {
		t.Error("expected write error on body, got nil")
	}

	// Échec sur la deuxième écriture (la signature)
	if err := m.WriteBinary(&secondWriteFails{}); err == nil {
		t.Error("expected write error on signature, got nil")
	}
}

// TestTruncateNullTerminated_SliceLargerThanMax couvre la branche src = src[:maxLen].
// Les callers normaux ne la déclenchent jamais (ils passent toujours field[:] avec maxLen=len(field)).
func TestTruncateNullTerminated_SliceLargerThanMax(t *testing.T) {
	// len(src)=6 > maxLen=3 → clip à [:3] = {'a','b',0} → retourne "ab"
	src := []byte{'a', 'b', 0, 'd', 'e', 'f'}
	got := truncateNullTerminated(src, 3)
	if string(got) != "ab" {
		t.Errorf("got %q, want %q", got, "ab")
	}
}

// TestSetAVEngine_Truncation vérifie que les noms d'engine trop longs sont tronqués.
func TestSetAVEngine_Truncation(t *testing.T) {
	m := &MFT{}
	long := strings.Repeat("x", len(m.Analysis.AVEngine)+5) // > 31 chars
	m.SetAVEngine(long)
	got := m.GetAVEngine()
	if len(got) >= len(m.Analysis.AVEngine) {
		t.Errorf("SetAVEngine truncation failed: got len=%d", len(got))
	}
}

// TestSetAnalyzerVersion_Truncation vérifie que les versions trop longues sont tronquées.
func TestSetAnalyzerVersion_Truncation(t *testing.T) {
	m := &MFT{}
	m.SetAnalyzerVersion("1234567890123456") // 16 chars > max 15
	got := m.GetAnalyzerVersion()
	if len(got) > 15 {
		t.Errorf("SetAnalyzerVersion truncation failed: got len=%d", len(got))
	}
}

// buildSerializedMFT construit et sérialise un MFT minimal pour les tests ReadBinary.
func buildSerializedMFT(t *testing.T) []byte {
	t.Helper()
	data := bytes.Repeat([]byte{0x01}, 512)
	path := writeTempFile(t, data)
	privKey := generateKey(t)
	m, err := buildFromFile(path, privKey, 256)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := m.WriteBinary(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestReadBinary_IncompleteSections vérifie les erreurs sur des données tronquées.
// On lit les longueurs de section depuis le header pour calculer dynamiquement les offsets.
func TestReadBinary_IncompleteSections(t *testing.T) {
	mftData := buildSerializedMFT(t)

	// Header layout (48 bytes):
	// [4 Magic][1 Version][3 ContentLen][3 AnalysisLen][3 UploaderLen][3 PreviewLen][3 ChunkLen][1 Flags][27 Reserved]
	contentLen  := int(bytesToUint24([3]byte{mftData[5], mftData[6], mftData[7]}))
	analysisLen := int(bytesToUint24([3]byte{mftData[8], mftData[9], mftData[10]}))
	uploaderLen := int(bytesToUint24([3]byte{mftData[11], mftData[12], mftData[13]}))
	previewLen  := int(bytesToUint24([3]byte{mftData[14], mftData[15], mftData[16]}))
	chunkLen    := int(bytesToUint24([3]byte{mftData[17], mftData[18], mftData[19]}))

	hdr := binary.Size(Header{})     // 48
	off := hdr + contentLen          // début de Analysis
	offChunks := off + analysisLen   // début de Chunks
	offUpload := offChunks + chunkLen // début de Uploaders
	offAuthor := offUpload + uploaderLen // début de Author
	offPreview := offAuthor + 32      // début de Preview

	tests := []struct {
		name     string
		truncate int
	}{
		{"incomplete_content",  hdr + 1},
		{"incomplete_analysis", off + 1},
		{"incomplete_chunks",   offChunks + 1},
		{"incomplete_author",   offAuthor + 1},
		// Après tout le corps, mais trop court pour loger les 64 bytes de signature
		{"short_for_signature", offPreview + previewLen + 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.truncate >= len(mftData) {
				t.Skipf("truncation point %d >= full mft size %d", tt.truncate, len(mftData))
			}
			m := &MFT{}
			if err := m.ReadBinary(bytes.NewReader(mftData[:tt.truncate])); err == nil {
				t.Errorf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

// TestVerifyFileHash_StatError vérifie l'erreur quand le fichier source n'est pas accessible.
func TestVerifyFileHash_StatError(t *testing.T) {
	data := bytes.Repeat([]byte{0x01}, 512)
	path := writeTempFile(t, data)
	privKey := generateKey(t)

	m, _ := buildFromFile(path, privKey, 256)

	// Fichier supprimé après la construction
	if err := m.VerifyFileHash("/nonexistent/file.bin"); err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

// TestParseTags_IgnoresLongTags vérifie que parseTags filtre les tags dépassant MaxTagLen.
func TestParseTags_IgnoresLongTags(t *testing.T) {
	m := &MFT{}
	longTag := strings.Repeat("x", MaxTagLen+1)
	// Construire les données brutes : "ok\0<long>\0"
	data := append([]byte("ok\x00"), append([]byte(longTag), 0)...)
	if err := m.parseTags(data); err != nil {
		t.Fatalf("parseTags: %v", err)
	}
	if len(m.Tags) != 1 || m.Tags[0] != "ok" {
		t.Errorf("Tags = %v, want [\"ok\"]", m.Tags)
	}
}
