pub mod rsa {
    use std::path::Path;

    use crate::key::rsa::get_private_key;
    use rsa::{PaddingScheme, RsaPrivateKey};

    use crate::file::read_file_bytes;

    pub fn decrypt_data(
        data: Vec<u8>,
        private_key: RsaPrivateKey,
    ) -> Result<Vec<u8>, rsa::errors::Error> {
        private_key.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &data)
    }

    pub fn decrypt_data_with_key_file(
        data: Vec<u8>,
        private_key_path: impl AsRef<Path>,
    ) -> Result<Vec<u8>, rsa::errors::Error> {
        decrypt_data(data, get_private_key(private_key_path))
    }

    pub fn decrypt_data_file(
        file_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
    ) -> Result<Vec<u8>, rsa::errors::Error> {
        decrypt_data_with_key_file(
            read_file_bytes(file_path).expect("Failed to read the data file"),
            private_key_path,
        )
    }
}

#[cfg(test)]
mod rsa_test {

    #[cfg(test)]
    mod decrypt {
        use super::super::rsa::decrypt_data_file;

        #[test]
        fn decrypts_data_file() {
            let key_path = "test-files/keys/decryption-key.pem";
            let data_path = "test-files/encrypted-files/test-read-file.encrypted";
            let expected_decrypted_data = String::from("qwerty");

            let decrypted_data = decrypt_data_file(data_path, key_path).unwrap();

            assert_eq!(
                String::from_utf8(decrypted_data).unwrap(),
                expected_decrypted_data
            );
        }
    }
}
