pub mod rsa {
    use std::path::PathBuf;

    use rsa::{PaddingScheme, PublicKey};

    use crate::file::read_file_bytes;
    use crate::key::rsa::get_public_key;

    pub fn encrypt_data(data: Vec<u8>, public_key_path: &PathBuf) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let public_key = get_public_key(public_key_path);

        public_key
            .encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(), &data)
            .expect("Failed to encrypt file")
    }

    pub fn encrypt_data_file(file_path: &PathBuf, public_key_path: &PathBuf) -> Vec<u8> {
        let data = read_file_bytes(file_path).expect("Failed to read data file");

        encrypt_data(data, public_key_path)
    }
}
