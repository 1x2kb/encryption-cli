pub mod rsa {
    use crate::key::rsa::get_private_key;
    use rsa::PaddingScheme;

    use crate::file::read_file_bytes;

    pub fn decrypt_data(data: Vec<u8>, private_key_path: &str) -> Vec<u8> {
        let private_key = get_private_key(private_key_path);

        private_key
            .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &data)
            .expect("Failed to decrypt file")
    }

    pub fn decrypt_data_file(file_path: &str, private_key_path: &str) -> Vec<u8> {
        decrypt_data(read_file_bytes(file_path), private_key_path)
    }
}
