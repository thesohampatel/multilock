# multilock 🔐

A secure multi-layer encryption tool written in Rust.  
It derives keys from the **binary filename** itself, making the executable both the key and the tool.  

## ✨ Features
- **Argon2id + random salt** → strong, unique per-message keys  
- **HKDF-SHA512** → clean key separation (AES & XChaCha20)  
- **AES-256-GCM** inner layer  
- **XChaCha20-Poly1305** outer layer with AAD (binds ciphertext to filename & version)  
- **Zeroizes sensitive key material** in memory  
- **Cross-platform builds**:
  - Apple Silicon (M1/M2) macOS  
  - Linux (x86_64-musl, static binary)  
  - Raspberry Pi (aarch64-musl, static binary)  

---

## ⚙️ Build Instructions

### macOS (Apple Silicon M1/M2)
```bash
cargo build --release
ls target/release/multilock
```

### Linux x86_64 (musl, static)
```bash
cargo build --release --target x86_64-unknown-linux-musl
ls target/x86_64-unknown-linux-musl/release/multilock
```

### Raspberry Pi (aarch64-musl, static)
```bash
cargo build --release --target aarch64-unknown-linux-musl
ls target/aarch64-unknown-linux-musl/release/multilock
```

> **Note:** requires cross toolchains:
```bash
brew tap messense/macos-cross-toolchains
brew install x86_64-unknown-linux-musl aarch64-unknown-linux-musl
brew link x86_64-unknown-linux-musl
brew link aarch64-unknown-linux-musl
```

---

## 🚀 Usage

### Encrypt a string
```bash
./multilock -e "Hello World"
```
Output → JSON package:
```json
{
  "v": 2,
  "s": "c29tZXNhbHQ=",
  "n1": "YWVzLW5vbmNl",
  "n2": "eGNoYWNoYTIwLW5vbmNl",
  "ct": "YmFzZTY0LWVuY3J5cHRlZA=="
}
```

### Decrypt a package
```bash
./multilock -d '{"v":2,"s":"...","n1":"...","n2":"...","ct":"..."}'
```
Output:
```
Hello World
```

---

### Encrypt file contents
```bash
./multilock -e "$(cat secret.txt)" > encrypted.json
```

### Decrypt file contents
```bash
./multilock -d "$(cat encrypted.json)" > decrypted.txt
```

---

### Binary binding to filename
- The executable name **is the key**.  
- Example:
  ```bash
  cp target/release/multilock ./securetool
  ./securetool -e "test"
  ./multilock -d "<package>"   # ❌ fails
  ./securetool -d "<package>"  # ✅ works
  ```

This prevents ciphertext reuse across renamed binaries.

---

## 📦 Package Format (v2)
Each ciphertext is a JSON object:

| Field | Description |
|-------|-------------|
| `v`   | Version (2) |
| `s`   | Argon2 salt (base64, 16 bytes) |
| `n1`  | AES-GCM nonce (base64, 12 bytes) |
| `n2`  | XChaCha20-Poly1305 nonce (base64, 24 bytes) |
| `ct`  | Outer ciphertext (base64) |

---

## 🔒 Security Notes
- Keys are **derived per message** using Argon2id + random salt.  
- **HKDF-SHA512** splits into two independent keys (AES & XChaCha20).  
- **Outer AEAD** binds ciphertext to executable filename (AAD).  
- **Zeroization** wipes secrets in memory after use.  

---

## 📜 License
MIT License
See [LICENSE](LICENSE) for details.