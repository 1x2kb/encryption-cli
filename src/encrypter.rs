pub mod rsa {
    use std::path::Path;

    use rsa::{PaddingScheme, PublicKey, RsaPublicKey};

    use crate::file::read_file_bytes;
    use crate::key::rsa::get_public_key;

    pub fn encrypt_data(
        data: Vec<u8>,
        public_key: RsaPublicKey,
    ) -> Result<Vec<u8>, rsa::errors::Error> {
        let mut rng = rand::thread_rng();

        public_key.encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(), &data)
    }

    pub fn encrypt_data_file(
        file_path: impl AsRef<Path>,
        public_key_path: impl AsRef<Path>,
    ) -> Result<Vec<u8>, rsa::errors::Error> {
        let data = read_file_bytes(file_path).expect("Failed to read data file");

        encrypt_data(data, get_public_key(public_key_path))
    }
}

#[cfg(test)]
mod rsa_test {

    #[cfg(test)]
    mod encrypts_data {
        use crate::{
            encrypter::rsa::{encrypt_data, encrypt_data_file},
            key::rsa::get_public_key,
        };

        #[test]
        fn encrypts_raw_data() {
            let data_path = "test-files/test-read-file.txt";
            let key_path = "test-files/keys/encryption-key.pem";

            let unencrypted_data = std::fs::read(data_path).unwrap();

            let encrypted_data =
                encrypt_data(unencrypted_data.clone(), get_public_key(key_path)).unwrap();
            assert_ne!(unencrypted_data.len(), encrypted_data.len());
            let encrypted_file_bytes =
                std::fs::read("test-files/encrypted-files/test-read-file.encrypted").unwrap();
            assert_ne!(encrypted_data, encrypted_file_bytes);
        }

        #[test]
        fn encrypts_data_from_files() {
            let data_path = "test-files/test-read-file.txt";
            let key_path = "test-files/keys/encryption-key.pem";

            let encrypted_data = encrypt_data_file(data_path, key_path).unwrap();

            let unencrypted_data = std::fs::read(data_path).unwrap();
            assert_ne!(unencrypted_data.len(), encrypted_data.len());
            let encrypted_file_bytes =
                std::fs::read("test-files/encrypted-files/test-read-file.encrypted").unwrap();
            assert_ne!(encrypted_data, encrypted_file_bytes);
        }
    }
}
