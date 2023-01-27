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

    pub fn decrypt_data_file(
        file_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
    ) -> Result<Vec<u8>, rsa::errors::Error> {
        decrypt_data(
            read_file_bytes(file_path).expect("Failed to read the data file"),
            get_private_key(private_key_path),
        )
    }
}

#[cfg(test)]
mod rsa_test {

    #[cfg(test)]
    mod decrypt {
        use crate::{decrypter::rsa::decrypt_data, key::rsa::get_private_key};

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

        #[test]
        fn decrypts_data() {
            let key_path = "test-files/keys/decryption-key.pem";
            let encrypted_data_path = "test-files/encrypted-files/test-read-file.encrypted";
            let expected_decrypted_data = String::from("qwerty");

            let encrypted_data = std::fs::read(encrypted_data_path).unwrap();
            let key = get_private_key(key_path);

            let decrypted_data = decrypt_data(encrypted_data, key).unwrap();

            let decrypted_data = String::from_utf8(decrypted_data).unwrap();

            assert_eq!(decrypted_data, expected_decrypted_data);
        }
    }
}
