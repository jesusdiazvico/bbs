use bbs::prelude::*;
use rand::SeedableRng;

fn main() {
    // initialize the BBS ciphersuite
    let bbs = Bbs::<Bls12381Sha256>::default();

    // encoded message data
    let data = [
        // disclosed idx 0
        bbs.message("I ❤️ BBS"),
        // encrypted idx 1
        bbs.message("I am 42 years old"),
        // disclosed idx 2
        bbs.message("I also ❤️ Rust"),
        bbs.message("I also ❤️ Linux"),
        // encrypted idx 4
        bbs.message("I discovered Linux when I was 10 years old"),
        // disclosed idx 5
        bbs.message("I also ❤️ Cryptography"),
        // encrypted idx 6
        bbs.message("The secret code is 392"),
        bbs.message("And of course I ❤️ zero knowledge!"),
        bbs.message("Pie is better than cake"),
        // disclosed idx 9
        bbs.message("My actual name is Alexandros"),
        bbs.message("Pineapple on pizza is a crime"),
        // encrypted idx 11
        bbs.message("I know exactly 382 things"),
        // encrypted idx 12
        bbs.message("My favorite number is 11."),
        bbs.message("Blame copilot for these messages"),
    ];
    // encrypted indices: [1,4,6,11,12]
    // disclosed indices: [0,2,5,9]
    println!("messages: {:#?\n}", data);

    let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);

    // generate a random elgamal key
    let (pk_eg, sk_eg) = keygen(&mut rng);

    // generate a random bbs key
    let sk_bbs = SecretKey::random::<Bls12381Sha256>();
    println!("secret key: {:?}\n", sk_bbs);

    let pk_bbs = sk_bbs.public_key();
    println!("public key: {:?}\n", pk_bbs);

    // sign the messages
    let signature = bbs.sign(&sk_bbs, &data);
    println!("signature: {:?}\n", signature);

    // verify the signature
    let res = bbs.verify(&pk_bbs, &signature, &data);
    println!("verify signature result: {:?}\n", res);

    // encrypt the 5-th message
    let r1 = sample_randomness(&mut rng);
    let r2 = sample_randomness(&mut rng);
    let r3 = sample_randomness(&mut rng);
    let r4 = sample_randomness(&mut rng);
    let r5 = sample_randomness(&mut rng);
    let ciphertext = &[
        encrypt(pk_eg, data[1], r1),
        encrypt(pk_eg, data[4], r2),
        encrypt(pk_eg, data[6], r3),
        encrypt(pk_eg, data[11], r4),
        encrypt(pk_eg, data[12], r5),
    ];

    // create a proof by disclosing the messages at indices 1 and 3 and encrypting message at index 5
    let proof = bbs
        .create_proof_with_enc(
            &pk_bbs,
            &pk_eg,
            &signature,
            ciphertext,
            &[r1, r2, r3, r4, r5],
            &data,
            &[0, 2, 5, 9],
            &[1, 4, 6, 11, 12],
        )
        .unwrap();
    println!("proof: {:?}\n", proof);
    println!("proof length: {:?} bytes\n", proof.to_bytes().len());

    let disclosed_data = [data[0], data[2], data[5], data[9]];
    println!("disclosed messages: {:#?}\n", disclosed_data);

    // verify the generated proof
    let res = bbs.verify_proof_with_enc(&pk_bbs, &pk_eg, ciphertext, &proof, &disclosed_data, &[0, 2, 5, 9], &[1, 4, 6, 11, 12]);
    println!("verify proof result: {:?}\n", res.unwrap());

    // decrypt the message
    let message_set1 = (0..100).map(|x| format!("I am {} years old", x)).collect::<Vec<_>>();
    let message_set2 = (0..100)
        .map(|x| format!("I discovered Linux when I was {} years old", x))
        .collect::<Vec<_>>();
    let message_set3 = (0..1000).map(|x| format!("The secret code is {}", x)).collect::<Vec<_>>();
    let message_set4 = (0..1000).map(|x| format!("I know exactly {} things", x)).collect::<Vec<_>>();
    let message_set5 = (0..100).map(|x| format!("My favorite number is {}.", x)).collect::<Vec<_>>();

    let decrypted_message1 = decrypt(&sk_eg, &ciphertext[0], message_set1);
    let decrypted_message2 = decrypt(&sk_eg, &ciphertext[1], message_set2);
    let decrypted_message3 = decrypt(&sk_eg, &ciphertext[2], message_set3);
    let decrypted_message4 = decrypt(&sk_eg, &ciphertext[3], message_set4);
    let decrypted_message5 = decrypt(&sk_eg, &ciphertext[4], message_set5);

    println!("decrypted_message: {:?}", decrypted_message1);
    println!("decrypted_message: {:?}", decrypted_message2);
    println!("decrypted_message: {:?}", decrypted_message3);
    println!("decrypted_message: {:?}", decrypted_message4);
    println!("decrypted_message: {:?}", decrypted_message5);
}
