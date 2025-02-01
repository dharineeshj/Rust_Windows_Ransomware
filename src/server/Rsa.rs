use rsa::{RsaPrivateKey, RsaPublicKey,Pkcs1v15Encrypt};
use rand::rngs::OsRng;
pub unsafe fn key_generation()->(RsaPublicKey,RsaPrivateKey){
    let mut rng = OsRng;
    let bits = 1024; 
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);
    (pub_key.clone(),priv_key.clone())
}
