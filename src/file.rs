use std::{fs, path::PathBuf};

pub fn read_file_string(path: &str) -> String {
    fs::read_to_string(path).expect("Failed to read in the private key. Terminating execution")
}

pub fn read_file_bytes(path: &str) -> Vec<u8> {
    fs::read(path).expect("Failed to read data file")
}

pub fn write_file(data: Vec<u8>, path: &str) -> Result<(), std::io::Error> {
    fs::write(path, data)
}

pub fn canonicalize(path: &PathBuf) -> Result<std::path::PathBuf, std::io::Error> {
    fs::canonicalize(path)
}

pub fn file_name(path: &PathBuf) -> String {
    let file_name = match path.file_name() {
        Some(file_name) => file_name,
        None => panic!("No file name given for data path. Cannot generate a file name"),
    };

    match file_name.to_str() {
        Some(str_rep) => str_rep.to_string(),
        None => panic!("Failed to create path string from os str"),
    }
}

pub fn file_extension(path: &PathBuf) -> String {
    let extension = match path.extension() {
        Some(extension_os_str) => extension_os_str,
        None => panic!("Could not get extension from file path"),
    };

    match extension.to_str() {
        Some(extension_str) => extension_str.to_string(),
        None => panic!("Could not create an extension string from os str"),
    }
}
