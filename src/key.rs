pub mod rsa {

    use std::path::{Path};

    use rsa::{
        pkcs8::{DecodePrivateKey, DecodePublicKey},
        RsaPrivateKey, RsaPublicKey,
    };

    use crate::file::read_file_string;

    pub fn get_private_key(path: impl AsRef<Path>) -> RsaPrivateKey {
        RsaPrivateKey::from_pkcs8_pem(&read_file_string(path))
            .expect("Failed to create private key from key file")
    }

    pub fn get_public_key(path: impl AsRef<Path>) -> RsaPublicKey {
        RsaPublicKey::from_public_key_pem(&read_file_string(path))
            .expect("Failed to create public key from key file")
    }

    pub fn generate_key_pairs(bit_length: usize) -> Result<(RsaPublicKey, RsaPrivateKey), String> {
        if bit_length != 2048 && bit_length != 4096 {
            let supported_lengths: String = vec![2048, 4096]
                .iter()
                .map(|bit_length: &usize| bit_length.to_string())
                .collect::<Vec<String>>()
                .join(", ");

            return Result::Err(format!(
                "Unsupported bit length: {}, supported bit lengths are: {}",
                bit_length, supported_lengths
            ));
        }

        let private_key = generate_private_key(bit_length);
        Result::Ok((generate_public_key(&private_key), private_key))
    }

    pub fn generate_public_key(private_key: &RsaPrivateKey) -> RsaPublicKey {
        RsaPublicKey::from(private_key)
    }

    pub fn generate_private_key(bit_length: usize) -> RsaPrivateKey {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, bit_length).expect("failed to generate a key")
    }
}
