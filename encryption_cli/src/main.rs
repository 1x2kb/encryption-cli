extern crate pretty_env_logger;

extern crate log;

use std::env::current_dir;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use std::fs;

use clap::{Parser, Subcommand};
use decrypter::rsa::decrypt_data_file;
use encrypter::rsa::encrypt_data_file;
use file::write_file;
use keys::rsa::generate_key_pairs;
use log::{debug, info, warn};

use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

#[derive(Parser)]
struct Cli {
    #[arg(short, long, help = "test")]
    rust_level: Option<String>,
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
        data_path: OsString,
        /// Path to the encryption key.
        key_path: OsString,
        output_path: Option<OsString>,
    },
    DecryptRsa {
        data_path: String,
        key_path: String,
        output_path: String,
    },
}

fn main() {
    let cli = Cli::parse();
    pretty_env_logger::init();

    match &cli.command {
        Some(Commands::GenerateKeys { output_dir, bits }) => {
            generate_keys(output_dir, bits);
        }
        Some(Commands::EncryptRsa {
            data_path,
            key_path,
            output_path,
        }) => encrypt_file(data_path, key_path, output_path),
        Some(Commands::DecryptRsa {
            data_path,
            key_path,
            output_path,
        }) => decrypt_file(
            data_path.to_string(),
            key_path.to_string(),
            output_path.to_string(),
        ),
        None => warn!("No command matched"),
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
    info!("Wrote decryption key to path: {}", &decryption_path);

    public_key
        .write_public_key_pem_file(&encryption_path, rsa::pkcs8::LineEnding::LF)
        .unwrap();

    info!("Wrote encryption key to path: {}", &encryption_path);
}

fn encrypt_file(data_path: &OsString, key_path: &OsString, output_path: &Option<OsString>) {
    debug!("Canonicalizing data path");
    let data_path = fs::canonicalize(data_path).expect("Failed to canonicalize data path");
    info!("Finalized data path: {}", &data_path.to_str().unwrap_or(""));

    debug!("Canonicalizing key path");
    let key_path = fs::canonicalize(key_path).expect("Failed to canonicalize key path");
    info!("Finalized key path: {}", data_path.to_str().unwrap_or(""));

    let data_file_name = Path::new(&data_path).file_stem().unwrap().to_os_string();

    let mut current_director = set_default_encryption_path();
    current_director.set_file_name(data_file_name.as_os_str());
    current_director.set_extension("encrypted");
    let current_director = current_director.as_os_str().to_os_string();

    debug!("Creating output directory");
    let write_path = output_path.as_ref().unwrap_or(&current_director);
    let write_path = file::normalize_path(Path::new(&write_path));
    info!(
        "Finalized encrypted file path {}",
        write_path.to_str().unwrap_or("")
    );

    let data = encrypt_data_file(data_path, key_path).expect("Failed to encrypt file");

    file::write_file(data, write_path).expect("Failed to write encrypted file");
}

fn decrypt_file(data_path: String, key_path: String, output_path: String) {
    info!("Decrypting file");

    debug!("Canonicalizing data path");
    let data_path = fs::canonicalize(data_path).expect("Failed to canonicalize data path");

    debug!("Canonicalizing data path");
    let key_path = fs::canonicalize(key_path).expect("Failed to canonicalize key path");

    info!("Successfully canonicalized data path and key path");

    debug!("Parsing output path");
    let output_path = Path::new(output_path.as_str());
    let output_path = file::normalize_path(output_path);

    let data = decrypt_data_file(data_path, key_path).expect("Failed to decrypt given data file");

    write_file(data, output_path).expect("Failed to write the decrypted file");
}

fn set_default_encryption_path() -> PathBuf {
    let mut output_path = current_dir().unwrap();
    if let Some(file_name) = output_path.file_name() {
        output_path.push(std::ffi::OsStr::to_os_string(file_name));
    }

    output_path
}
