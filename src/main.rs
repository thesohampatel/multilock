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
use zeroize::Zeroize;
use argon2::Argon2;

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

    let mut master = [0u8; 64];
    Argon2::default()
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

fn encrypt(plain: &[u8], exe_name: &str) -> String {
    let cname = cleaned_name(exe_name);

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let (k1, k2) = derive_keys_from_name_and_salt(&cname, &salt);

    // Inner AES-256-GCM
    let aead1 = Aes256Gcm::new_from_slice(&k1).unwrap();
    let mut n1 = [0u8; 12];
    OsRng.fill_bytes(&mut n1);
    let nonce1 = AesNonce::from_slice(&n1);
    let ct1 = aead1.encrypt(nonce1, plain).expect("AES-GCM encrypt");

    // Outer XChaCha20-Poly1305 with AAD binding to version + cleaned name
    let aead2 = XChaCha20Poly1305::new_from_slice(&k2).unwrap();
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
        .expect("XChaCha20 encrypt");

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

    serde_json::to_string(&package).unwrap()
}

fn decrypt(package_json: &str, exe_name: &str) -> Vec<u8> {
    let pkg: Package = serde_json::from_str(package_json).expect("parse json");

    let salt = general_purpose::STANDARD.decode(&pkg.s).unwrap();
    let n1 = general_purpose::STANDARD.decode(&pkg.n1).unwrap();
    let n2 = general_purpose::STANDARD.decode(&pkg.n2).unwrap();
    let ct2 = general_purpose::STANDARD.decode(&pkg.ct).unwrap();

    let cname = cleaned_name(exe_name);
    let (k1, k2) = derive_keys_from_name_and_salt(&cname, &salt);

    let aead2 = XChaCha20Poly1305::new_from_slice(&k2).unwrap();
    let aad = format!("v=2|{}", cname);
    let ct1 = aead2
        .decrypt(
            XNonce::from_slice(&n2),
            Payload {
                msg: ct2.as_ref(),
                aad: aad.as_bytes(),
            },
        )
        .expect("XChaCha20 decrypt");

    let aead1 = Aes256Gcm::new_from_slice(&k1).unwrap();
    let nonce1 = AesNonce::from_slice(&n1);
    let plain = aead1
        .decrypt(nonce1, ct1.as_ref())
        .expect("AES-GCM decrypt");

    let mut k1z = k1;
    let mut k2z = k2;
    k1z.zeroize();
    k2z.zeroize();

    plain
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <-e|-d> <data>", args[0]);
        std::process::exit(1);
    }

    let exe_name = exe_name_from_current_exe();
    match args[1].as_str() {
        "-e" => {
            let out = encrypt(args[2].as_bytes(), &exe_name);
            println!("{}", out);
        }
        "-d" => {
            let plain = decrypt(&args[2], &exe_name);
            if let Ok(s) = str::from_utf8(&plain) {
                println!("{}", s);
            } else {
                println!("{}", general_purpose::STANDARD.encode(&plain));
            }
        }
        _ => {
            eprintln!("Use -e (encrypt) or -d (decrypt)");
            std::process::exit(1);
        }
    }
}