mod decrypter;
mod encrypter;
mod file;
mod key;

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::{env::current_dir, path::PathBuf};

use crate::encrypter::rsa::encrypt_data_file;
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
        }) => encrypt_file(data_path.to_string(), key_path.to_string()),
        None => panic!("No bit length specified"),
    }
}

fn generate_keys(output_dir: &Option<String>, bits: &usize) {
    let (public_key, private_key) = generate_key_pairs(*bits).unwrap();
    let directory = output_dir
        .clone()
        .unwrap_or_else(|| current_dir().unwrap().to_str().unwrap().to_string());

    let decryption_path = format!("{}/{}", directory, "decryption-key.pem");
    let encryption_path = format!("{}/{}", directory, "encryption-key.pem");

    private_key
        .write_pkcs8_pem_file(&decryption_path, rsa::pkcs8::LineEnding::LF)
        .unwrap();
    println!("Wrote decryption key to path: {}", decryption_path);

    public_key
        .write_public_key_pem_file(&encryption_path, rsa::pkcs8::LineEnding::LF)
        .unwrap();
    println!("Wrote encryption key to path: {}", &encryption_path);
}

fn encrypt_file(data_path: String, key_path: String) {
    let data_path = PathBuf::from(data_path.as_str());
    let data_path = fs::canonicalize(data_path).expect("Failed to canonicalize data path");

    let key_path = PathBuf::from(key_path.as_str());
    let key_path = fs::canonicalize(key_path).expect("Failed to canonicalize key path");

    let mut data_file_name = Path::new(&data_path).file_stem().unwrap().to_os_string();
    data_file_name.push(OsString::from(".encrypted"));

    let mut write_path = current_dir().expect("Could not generate a current directory");
    write_path.push(data_file_name);

    println!("{}", write_path.to_str().unwrap());

    let _data = encrypt_data_file(&data_path, &key_path);

    // file::write_file(data, format!("{}/{}", write_path, data_file_name).as_str()).unwrap();
}
