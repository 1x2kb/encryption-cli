use std::{fs, path::{Path}};

pub fn read_file_string(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path).expect("Failed to read in the private key. Terminating execution")
}

pub fn read_file_bytes(path: impl AsRef<Path>) -> Vec<u8> {
    fs::read(path).expect("Failed to read data file")
}

pub fn write_file(data: Vec<u8>, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
    fs::write(path, data)
}
