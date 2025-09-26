use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use aead::{Aead, KeyInit, Payload};
use hkdf::Hkdf;
use sha2::Sha512;
use rand::rngs::OsRng;
use rand::RngCore;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::env;
use std::str;
use std::fs;
use zeroize::Zeroize;
use argon2::{Argon2, Params};
use std::io::Read;

#[derive(Serialize, Deserialize)]
struct Package {
    v: u8,      // version
    s: String,  // Argon2 salt (base64)
    n1: String, // AES-GCM nonce (12 bytes, base64)
    n2: String, // XChaCha20 nonce (24 bytes, base64)
    ct: String, // ciphertext (base64)
}

/// Produce cleaned filename (spaces→'_' then reversed)
fn cleaned_name(exe_name: &str) -> String {
    let cleaned = exe_name.replace(' ', "_");
    cleaned.chars().rev().collect()
}

/// Derive two 32-byte keys from Argon2id(master) → 64 bytes, then HKDF-SHA512 split
fn derive_keys_from_name_and_salt(name: &str, salt: &[u8]) -> ([u8; 32], [u8; 32]) {
    let pwd = name.as_bytes();

    // Use Argon2id with moderate params (t=2, m=65536, p=1)
    let params = Params::new(65536, 2, 1, None).expect("argon params");
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut master = [0u8; 64];
    argon
        .hash_password_into(pwd, salt, &mut master)
        .expect("argon2");

    let hk = Hkdf::<Sha512>::new(Some(salt), &master);
    let mut okm = [0u8; 64];
    hk.expand(b"headless_cli_kdf_v2", &mut okm)
        .expect("hkdf expand");

    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    k1.copy_from_slice(&okm[..32]);
    k2.copy_from_slice(&okm[32..64]);

    // wipe sensitive buffers
    let mut m = master;
    m.zeroize();
    let mut o = okm;
    o.zeroize();

    (k1, k2)
}

fn exe_name_from_current_exe() -> String {
    let path = env::current_exe().expect("exe path");
    let fname = path.file_name().and_then(|s| s.to_str()).expect("exe name");
    fname.to_string()
}

/// Read the 'data' argument. Supported forms:
/// - Leading '@' means read the file after the '@' (e.g. @data.json)
/// - A single dash "-" means read from stdin
/// - Otherwise treat as the literal JSON string
fn read_data_arg(arg: &str) -> Result<String, String> {
    if arg == "-" {
        // read entire stdin
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("failed to read stdin: {}", e))?;
        Ok(buf)
    } else if let Some(rest) = arg.strip_prefix('@') {
        fs::read_to_string(rest)
            .map_err(|e| format!("failed to read file '{}': {}", rest, e))
    } else if fs::metadata(arg).is_ok() {
        // If the argument is an existing file path, read it (convenience)
        fs::read_to_string(arg).map_err(|e| format!("failed to read file '{}': {}", arg, e))
    } else {
        Ok(arg.to_string())
    }
}

fn encrypt(plain: &[u8], exe_name: &str) -> Result<String, String> {
    let cname = cleaned_name(exe_name);

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let (k1, k2) = derive_keys_from_name_and_salt(&cname, &salt);

    // Inner AES-256-GCM
    let aead1 = Aes256Gcm::new_from_slice(&k1).map_err(|e| format!("AES init: {}", e))?;
    let mut n1 = [0u8; 12];
    OsRng.fill_bytes(&mut n1);
    let nonce1 = AesNonce::from_slice(&n1);
    let ct1 = aead1.encrypt(nonce1, plain).map_err(|e| format!("AES encrypt: {}", e))?;

    // Outer XChaCha20-Poly1305 with AAD binding to version + cleaned name
    let aead2 = XChaCha20Poly1305::new_from_slice(&k2).map_err(|e| format!("XChaCha init: {}", e))?;
    let mut n2 = [0u8; 24];
    OsRng.fill_bytes(&mut n2);
    let aad = format!("v=2|{}", cname);
    let ct2 = aead2
        .encrypt(
            XNonce::from_slice(&n2),
            Payload {
                msg: ct1.as_ref(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|e| format!("XChaCha encrypt: {}", e))?;

    let package = Package {
        v: 2,
        s: general_purpose::STANDARD.encode(&salt),
        n1: general_purpose::STANDARD.encode(&n1),
        n2: general_purpose::STANDARD.encode(&n2),
        ct: general_purpose::STANDARD.encode(&ct2),
    };

    // wipe keys
    let mut k1z = k1;
    let mut k2z = k2;
    k1z.zeroize();
    k2z.zeroize();

    serde_json::to_string(&package).map_err(|e| format!("serialize package: {}", e))
}

fn decrypt(package_json: &str, exe_name: &str) -> Result<Vec<u8>, String> {
    let pkg: Package = serde_json::from_str(package_json).map_err(|e| format!("parse json: {}", e))?;

    let salt = general_purpose::STANDARD.decode(&pkg.s).map_err(|e| format!("base64 salt: {}", e))?;
    let n1 = general_purpose::STANDARD.decode(&pkg.n1).map_err(|e| format!("base64 n1: {}", e))?;
    let n2 = general_purpose::STANDARD.decode(&pkg.n2).map_err(|e| format!("base64 n2: {}", e))?;
    let ct2 = general_purpose::STANDARD.decode(&pkg.ct).map_err(|e| format!("base64 ct: {}", e))?;

    let cname = cleaned_name(exe_name);
    let (k1, k2) = derive_keys_from_name_and_salt(&cname, &salt);

    let aead2 = XChaCha20Poly1305::new_from_slice(&k2).map_err(|e| format!("XChaCha init: {}", e))?;
    let aad = format!("v=2|{}", cname);
    let ct1 = aead2
        .decrypt(
            XNonce::from_slice(&n2),
            Payload {
                msg: ct2.as_ref(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|e| format!("XChaCha decrypt: {}", e))?;

    let aead1 = Aes256Gcm::new_from_slice(&k1).map_err(|e| format!("AES init: {}", e))?;
    let nonce1 = AesNonce::from_slice(&n1);
    let plain = aead1
        .decrypt(nonce1, ct1.as_ref())
        .map_err(|e| format!("AES-GCM decrypt: {}", e))?;

    let mut k1z = k1;
    let mut k2z = k2;
    k1z.zeroize();
    k2z.zeroize();

    Ok(plain)
}

fn print_usage(program: &str) {
    eprintln!("Usage: {} <-e|-d> <data>", program);
    eprintln!("Options for <data>:");
    eprintln!("  literal JSON string             (shell quoting required)");
    eprintln!("  @path/to/file.json              (read JSON from file)");
    eprintln!("  -                               (read JSON from stdin)");
    eprintln!("Examples:");
    eprintln!("  Unix/macOS: {} -d '@data.json'", program);
    eprintln!("  PowerShell:  .\\{} -d (Get-Content -Raw data.json)", program);
    eprintln!("  Windows (file): .\\{} -d @data.json", program);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    let exe_name = exe_name_from_current_exe();
    let op = args[1].as_str();
    match read_data_arg(&args[2]) {
        Err(e) => {
            eprintln!("Error reading data argument: {}", e);
            std::process::exit(2);
        }
        Ok(data) => {
            match op {
                "-e" => {
                    match encrypt(data.as_bytes(), &exe_name) {
                        Ok(out) => {
                            println!("{}", out);
                        }
                        Err(e) => {
                            eprintln!("Encryption failed: {}", e);
                            std::process::exit(3);
                        }
                    }
                }
                "-d" => {
                    match decrypt(&data, &exe_name) {
                        Ok(plain) => {
                            if let Ok(s) = str::from_utf8(&plain) {
                                println!("{}", s);
                            } else {
                                println!("{}", general_purpose::STANDARD.encode(&plain));
                            }
                        }
                        Err(e) => {
                            eprintln!("Decryption failed: {}", e);
                            std::process::exit(4);
                        }
                    }
                }
                _ => {
                    print_usage(&args[0]);
                    std::process::exit(1);
                }
            }
        }
    }
}
