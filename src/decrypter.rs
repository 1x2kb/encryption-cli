pub mod rsa {
    use std::path::Path;

    use crate::key::rsa::get_private_key;
    use rsa::PaddingScheme;

    use crate::file::read_file_bytes;

    pub fn decrypt_data(
        data: Vec<u8>,
        private_key_path: impl AsRef<Path>,
    ) -> Result<Vec<u8>, rsa::errors::Error> {
        let private_key = get_private_key(private_key_path);

        private_key.decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &data)
    }

    pub fn decrypt_data_file(
        file_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
    ) -> Result<Vec<u8>, rsa::errors::Error> {
        decrypt_data(
            read_file_bytes(file_path).expect("Failed to read the data file"),
            private_key_path,
        )
    }
}
