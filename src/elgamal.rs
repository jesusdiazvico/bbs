use bls12_381::{G1Projective, Scalar};
use ff::Field;
use rand::Rng;

use crate::{
    ciphersuite::Bls12381Sha256,
    encoding::{Ciphertext, EGPublikKey, EGSecretKey},
    prelude::Message,
    Bbs,
};

pub fn keygen<R: Rng>(rng: &mut R) -> (EGPublikKey, EGSecretKey) {
    let sk = EGSecretKey(<Scalar as Field>::random(rng));
    let pk = EGPublikKey(G1Projective::generator() * sk.0);
    (pk, sk)
}

pub fn sample_randomness<R: Rng>(rng: &mut R) -> Message {
    Message(<Scalar as Field>::random(rng))
}

pub fn encrypt(pk: EGPublikKey, message: Message, r: Message) -> Ciphertext {
    Ciphertext(r.0 * G1Projective::generator(), r.0 * pk.0 + G1Projective::generator() * message.0)
}

pub fn decrypt(sk: &EGSecretKey, ciphertext: &Ciphertext, message_set: Vec<String>) -> String {
    let bbs = Bbs::<Bls12381Sha256>::default();
    let plaintext_in_group = ciphertext.1 - sk.0 * ciphertext.0;
    let result = message_set
        .iter()
        .find(|msg| G1Projective::generator() * bbs.message(msg).0 == plaintext_in_group)
        .unwrap();
    String::from(result)
}
