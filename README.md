# 🔐 Multilock

**Multilock** is a lightweight, cross-platform command-line encryption tool written in Rust.  
It uses **Argon2id**, **HKDF-SHA512**, **AES-256-GCM**, and **XChaCha20-Poly1305** in a layered design, with executable filename binding for added protection.

## ✨ Features
- **Per-message unique keys** – random 16-byte salt per encryption.
- **Multi-layer AEAD encryption**:
  - Inner: AES-256-GCM
  - Outer: XChaCha20-Poly1305
- **Strong KDF** – Argon2id + HKDF-SHA512 key separation.
- **Tamper protection** – ciphertext bound to filename & version via AAD.
- **Zeroization** of sensitive material after use.
- Cross-platform builds:
  - ✅ macOS (Apple Silicon / Intel)
  - ✅ Linux (musl, static)

## 📦 Installation
### From Source
```bash
git clone https://github.com/thesohampatel/multilock.git
cd multilock
cargo build --release