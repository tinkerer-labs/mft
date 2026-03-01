# MFT — Media File Transfer

> Decentralized P2P media sharing over I2P — no central authority, no tracker server.

MFT is the open-source equivalent of YggTorrent/ruTorrent built on I2P. It enables anonymous, decentralized sharing of media files (movies, series, anime, music, games) using a custom `.mft` format, with full compatibility with \*arr applications (Prowlarr, Radarr, Sonarr, Lidarr).

---

## Features

- **Anonymous P2P** — all traffic routed through I2P, no IP exposure
- **Decentralized** — DHT-based peer discovery, no central server
- **Custom `.mft` format** — rich media metadata, chunked transfer, Ed25519 signatures
- **Security scanning** — integrated ClamAV + YARA scanner via Docker
- **\*arr compatible** — Torznab/Newznab API for Prowlarr, Radarr, Sonarr, Lidarr
- **Web UI** — built with Templ (Go)

---

## Architecture

```
DHT (peer discovery)          App-to-app (SAM v3)
─────────────────────         ──────────────────────────────
Key: mft-network-v1           HELLO / SYNC_CATALOGUE
Val: I2P dest + AppID         HAVE? / GET / CHUNKS
     + signature + ts         Bloom filter delta sync
```

**Two databases:**
- DHT — shared peer directory (minimal)
- BadgerDB — local full catalogue (G-Set CRDT, grow-only)

---

## Identity

Each peer has two independent identities:

| Identity | Purpose |
|---|---|
| **App ID** (Ed25519) | Stable network identity, signs all published content |
| **I2P Destination** | Network address, never reveals real IP |

The App ID remains constant even if the I2P destination changes — peers verify signatures independently.

---

## `.mft` Format

Binary file describing shared content — equivalent of `.torrent`.

```
[Header 48B][Content][Analysis][Chunks][Uploaders][Author 32B][Preview][Tags][Signature 64B]
```

- **Hash** — SHA3-512 of the full file
- **Chunks** — 1MB default, each chunk has its own SHA3-512 hash
- **Analysis** — ClamAV + YARA scan results, risk score 0–100
- **Signature** — Ed25519 over all serialized content

---

## Getting Started

### Prerequisites

- Go 1.25+
- i2pd (I2P router)
- Docker (for security scanning)

### Build

```bash
git clone https://github.com/tinkerer-labs/mft.git
cd mft
go build ./cmd/mft
```

### Configuration

Config file path via `MFT_CONFIG` env var, defaults to `./mft.yaml`.

Generated automatically on first run:

```yaml
identity:
  private_key: "base64..."   # Ed25519 seed (32 bytes)
  app_id: "hexstring..."     # public key hex (network identifier)
```

---

## Roadmap

- [x] App Identity (Ed25519)
- [ ] `.mft` format + chunked transfer
- [ ] BadgerDB + G-Set CRDT catalogue
- [ ] SAM v3 + I2P connection
- [ ] App-to-app protocol (sync, chunks)
- [ ] Download engine
- [ ] DHT + bootstrap
- [ ] Torznab/Newznab API
- [ ] Web UI (Templ)

---

## License

[AGPL-3.0](LICENSE) — © tinkerer-labs
