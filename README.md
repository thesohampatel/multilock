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

The project now uses [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) so a single toolchain (Zig) can cross-compile to every supported target without separate linker installs.

```bash
cargo install cargo-zigbuild   # once
# make sure zig is on PATH (brew install zig, pkg manager, etc.)
```

### macOS (Apple Silicon M1/M2)
```bash
cargo zigbuild --release --target aarch64-apple-darwin
ls target/aarch64-apple-darwin/release/multilock
```

### Windows (x86_64, GNU ABI)
```bash
cargo zigbuild --release --target x86_64-pc-windows-gnu
ls target/x86_64-pc-windows-gnu/release/multilock.exe
```

### Linux x86_64 (musl, static)
```bash
cargo zigbuild --release --target x86_64-unknown-linux-musl
ls target/x86_64-unknown-linux-musl/release/multilock
```

### Linux aarch64 (musl, static)
```bash
cargo zigbuild --release --target aarch64-unknown-linux-musl
ls target/aarch64-unknown-linux-musl/release/multilock
```

---

## 🚀 Usage

```
multilock <COMMAND> [OPTIONS] <DATA>
```

`<DATA>` can be supplied four ways:

- literal string/JSON passed directly on the command line (remember to quote)
- `@path/to/file` to read the entire file
- `-` to read from `stdin`
- an existing file path (without `@`) as a convenience shortcut

Encryption always returns a JSON package. Decryption emits UTF-8 plaintext when
possible, otherwise it base64-encodes the raw bytes for you.

### Commands
- `encrypt <DATA>` → encrypts input. Options: `--out <PATH>` to write to a file, `--pretty` to format the JSON output.
- `decrypt <DATA>` → decrypts a package. Options: `--out <PATH>` to write to a file, `--pretty` to format UTF-8 results, `--verify` to only check decryptability and print `OK`.

### Examples
#### Encrypt a string
```bash
multilock encrypt --pretty '{"msg":"Hello World"}'
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

#### Decrypt a package
```bash
multilock decrypt '{"v":2,"s":"...","n1":"...","n2":"...","ct":"..."}'
```
Output:
```
Hello World
```

#### Verify without printing plaintext
```bash
multilock decrypt --verify @encrypted.json
```
Output:
```
OK
```

#### Encrypt file contents
```bash
multilock encrypt @secret.txt --out encrypted.json
```

#### Decrypt file contents
```bash
multilock decrypt @encrypted.json --out decrypted.txt
```

You can also run the tool in-place during development:
```bash
cargo run -- encrypt --pretty '{"test":123}'
```

---

### Binary binding to filename
- The executable name **is the key**.  
- Example:
  ```bash
  cp target/release/multilock ./securetool
  ./securetool encrypt "test"
  ./multilock decrypt "<package>"   # ❌ fails
  ./securetool decrypt "<package>"  # ✅ works
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
