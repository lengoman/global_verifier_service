use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new RSA key pair
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);

    // Save the private key to a file
    private_key.write_pkcs1_pem_file("private_key.pem", LineEnding::LF)?;
    println!("Private key saved to private_key.pem");

    // Save the public key to a file
    public_key.write_pkcs1_pem_file("public_key.pem", LineEnding::LF)?;
    println!("Public key saved to public_key.pem");

    Ok(())
} 