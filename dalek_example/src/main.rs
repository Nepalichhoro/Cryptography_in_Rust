extern crate rand;
extern crate ed25519_dalek;
extern crate base64;

use ed25519_dalek::{Keypair, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use base64::{engine::general_purpose, Engine};

fn main() {
    // Generate a key pair
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);

    // The message to sign
    let message: &[u8] = b"This is a test message";

    // Sign the message
    let signature: Signature = keypair.sign(message);

    // Verify the signature
    match keypair.public.verify(message, &signature) {
        Ok(_) => println!("Signature is valid!"),
        Err(_) => println!("Signature is invalid!"),
    }

    // Serialize to Base64
    let public_key_base64 = general_purpose::STANDARD.encode(keypair.public.as_bytes());
    let secret_key_base64 = general_purpose::STANDARD.encode(keypair.secret.as_bytes());
    let signature_base64 = general_purpose::STANDARD.encode(signature.to_bytes());

    // Print the keys and signature in Base64
    println!("Public Key (Base64): {}", public_key_base64);
    println!("Private Key (Base64): {}", secret_key_base64);
    println!("Signature (Base64): {}", signature_base64);
    println!("Message: {}", String::from_utf8_lossy(message));
}
