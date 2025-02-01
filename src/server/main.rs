use warp::Filter;
use std::convert::Infallible;
use base64::{Engine as _, engine::general_purpose};
use rsa::{RsaPrivateKey, Pkcs1v15Encrypt};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
mod Rsa;
use prettytable::{Table, Row, Cell};

static mut PRIV_KEY: Option<RsaPrivateKey> = None;

#[tokio::main]
async fn main() {
    let send_key = warp::path("receive")
        .and(warp::get())
        .and_then(handle_get);

    let confirm_message = warp::path("confirm")
        .and(warp::post())
        .and(warp::body::bytes()) 
        .map(|body: bytes::Bytes| String::from_utf8_lossy(&body).into_owned()) 
        .and_then(handle_confirmation);

    let routes = send_key.or(confirm_message);

    println!("Waiting for any connections to be established");
    warp::serve(routes).run(([127, 0, 0, 1], 800)).await;
}

async fn handle_get() -> Result<impl warp::Reply, Infallible> {
    let response_message = "Server received your GET request"; 
    println!("{}", response_message); 
    
    let (pub_key, priv_key) = unsafe { Rsa::key_generation() };
    unsafe { PRIV_KEY = Some(priv_key); }
    let pub_key_der = pub_key.to_pkcs1_der().expect("Failed to convert public key to DER");
    
    let encoded_key = general_purpose::STANDARD.encode(&pub_key_der);

    Ok(warp::reply::with_status(encoded_key, warp::http::StatusCode::OK))
}

pub fn decryption(blob_buffer: &[u8]) -> Vec<u8> {
    unsafe {
        if let Some(ref priv_key) = PRIV_KEY {
            priv_key.decrypt(Pkcs1v15Encrypt, blob_buffer)
                .expect("failed to decrypt data")
        } else {
            panic!("Private key not initialized");
        }
    }
}

async fn handle_confirmation(confirmation_msg: String) -> Result<impl warp::Reply, Infallible> {
    println!("Received confirmation from client: {}", confirmation_msg);

    let decoded_blob = match general_purpose::STANDARD.decode(&confirmation_msg) {
        Ok(blob) => blob,
        Err(e) => {
            eprintln!("Failed to decode base64: {:?}", e);
            return Ok(warp::reply::with_status("Failed to decode base64", warp::http::StatusCode::BAD_REQUEST));
        }
    };
    let mut command = String::new();
    let decrypted_data = decryption(&decoded_blob);
    println!("\nDecrypted confirmation: {:?}", decrypted_data);
    let encoded_key = general_purpose::STANDARD.encode(&decrypted_data);
    println!("Encoded confirmation: {:?}", encoded_key);

    static mut KEY: Vec<Vec<u8>> = Vec::new();
    static mut ENCODED_KEY: Vec<String> = Vec::new();
    unsafe {
        KEY.push(decrypted_data.clone());
        ENCODED_KEY.push(encoded_key.clone());
    }
    
    print!("> ");
    std::io::stdin().read_line(&mut command).unwrap();
    
    if command.trim() == "show" {
        let mut table = Table::new();
        
        table.add_row(Row::new(vec![
            Cell::new(&format!("\x1b[1mS.NO\x1b[0m")),   
            Cell::new(&format!("\x1b[1mKey\x1b[0m")),    
            Cell::new(&format!("\x1b[1mEncoded Key\x1b[0m")), 
        ]));
        unsafe {
            for (i, key) in KEY.iter().enumerate() {
                let encoded_key = &ENCODED_KEY[i];
                table.add_row(Row::new(vec![
                    Cell::new(&i.to_string()),
                    Cell::new(&format!("{:?}", key)),
                    Cell::new(encoded_key),
                ]));
            }
        }
        table.printstd();  
    }
    Ok(warp::reply::with_status("Confirmation received", warp::http::StatusCode::OK))
}
