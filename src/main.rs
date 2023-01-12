mod decrypter;
mod encrypter;
mod file;
mod key;

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::{env::current_dir, path::PathBuf};

use crate::decrypter::rsa::decrypt_data_file;
use crate::encrypter::rsa::encrypt_data_file;
use crate::file::write_file;
use crate::key::rsa::generate_key_pairs;
use clap::{Parser, Subcommand};

use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generates public/private keys (named encryption/decryption respectively) to be used for encrypting and decrypting files.
    GenerateKeys {
        /// The path to write the generated keys.
        output_dir: Option<String>,
        #[arg(short, long, default_value_t = 4096usize)]
        bits: usize,
    },
    /// Encrypts a file using the RSA algorithm using the user specified key.
    EncryptRsa {
        /// Path to the file to encrypt.
        data_path: String,
        /// Path to the encryption key.
        key_path: String,
        output_path: Option<String>,
    },
    DecryptRsa {
        data_path: String,
        key_path: String,
        output_path: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::GenerateKeys { output_dir, bits }) => {
            generate_keys(output_dir, bits);
        }
        Some(Commands::EncryptRsa {
            data_path,
            key_path,
            output_path,
        }) => encrypt_file(data_path.to_string(), key_path.to_string(), output_path),
        Some(Commands::DecryptRsa {
            data_path,
            key_path,
            output_path,
        }) => decrypt_file(
            data_path.to_string(),
            key_path.to_string(),
            output_path.to_string(),
        ),
        None => panic!("No command matched"),
    }
}

fn generate_keys(output_dir: &Option<String>, bits: &usize) {
    let (public_key, private_key) = generate_key_pairs(*bits).unwrap();
    let directory = output_dir
        .clone()
        .unwrap_or_else(|| current_dir().unwrap().to_str().unwrap().to_string());

    let decryption_path = format!("{}/{}", directory, "decryption-key.pem");
    let encryption_path = format!("{}/{}", directory, "encryption-key.pem");

    // TODO: Make OS agnostic.
    private_key
        .write_pkcs8_pem_file(&decryption_path, rsa::pkcs8::LineEnding::LF)
        .unwrap();
    println!("Wrote decryption key to path: {}", decryption_path);

    public_key
        .write_public_key_pem_file(&encryption_path, rsa::pkcs8::LineEnding::LF)
        .unwrap();
    println!("Wrote encryption key to path: {}", &encryption_path);
}

fn encrypt_file(data_path: String, key_path: String, output_path: Option<String>) {
    let data_path = fs::canonicalize(data_path).expect("Failed to canonicalize data path");
    let key_path = fs::canonicalize(key_path).expect("Failed to canonicalize key path");
    let data_file_name = Path::new(&data_path).file_stem().unwrap();

    let mut write_path = current_dir().unwrap();
    // If file name is Some for the current directory, the current directory is the file name.
    if let Some(file_name) = write_path.file_name() {
        write_path.push(file_name.to_os_string());
    }
    write_path.set_file_name(data_file_name);
    write_path.set_extension("encrypted");

    println!("{}", write_path.to_str().unwrap());

    let data = encrypt_data_file(&data_path, &key_path);

    file::write_file(data, write_path).expect("Failed to write encrypted file");
}

fn decrypt_file(data_path: String, key_path: String, output_path: String) {
    let data_path = fs::canonicalize(data_path).expect("Failed to canonicalize data path");
    let key_path = fs::canonicalize(key_path).expect("Failed to canonicalize key path");

    let output_path = Path::new(output_path.as_str());
    let output_path = file::normalize_path(output_path);

    println!("{}", output_path.to_str().unwrap());

    let data = decrypt_data_file(data_path, key_path).expect("Failed to decrypt given data file");

    write_file(data, output_path).unwrap();
}
