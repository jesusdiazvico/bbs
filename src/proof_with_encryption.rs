use std::fmt::{self, Debug, Display, Formatter};

use std::mem;

use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar};
use rand::{thread_rng, Rng};

use crate::{
    ciphersuite::*,
    encoding::*,
    generators::*,
    signature::*,
    utils::{calculate_challenge_with_encryption, calculate_domain},
    Error,
};

#[derive(PartialEq, Eq, Clone)]
pub struct ProofWithEncrypted {
    A_bar: G1Projective,
    B_bar: G1Projective,
    C_bar: Vec<(G1Projective, G1Projective)>,
    U: G1Projective,
    U1: Vec<G1Projective>,
    U2: Vec<G1Projective>,
    V1: Vec<G1Projective>,
    V2: Vec<G1Projective>,
    s: Scalar,
    t: Scalar,
    u: Vec<Scalar>,
    v: Vec<Scalar>,
    rho: Scalar,
}

// TODO: Docs
#[allow(clippy::too_many_arguments)]
pub(crate) fn proof_with_enc_gen_impl<'a, T: BbsCiphersuite<'a>>(
    pk_bbs: &G2Projective,
    pk_elgamal: &G1Projective,
    signature: &Signature,
    ciphertext: &[(G1Projective, G1Projective)],
    c_randomness: &[Scalar],
    header: &[u8],
    ph: &[u8],
    messages: &[Scalar],
    disclosed_indices: &[usize],
    encrypted_indices: &[usize],
) -> ProofWithEncrypted {
    // full message length
    let L = messages.len();

    // disclosed attributes length
    let R = disclosed_indices.len();

    // encrypted attributes length
    let E = encrypted_indices.len();

    // undisclosed attributes length
    let U = L - R;

    // Assert indices are correct
    // 1. indices \in [0..L]
    disclosed_indices.iter().for_each(|&i| assert!(i < L));
    encrypted_indices.iter().for_each(|&i| assert!(i < L));

    // 2. encrypted indices and disclosed indices do not overlap
    encrypted_indices.iter().for_each(|i| assert!(!disclosed_indices.contains(i)));

    let mut disclosed_indices = disclosed_indices.to_vec();
    disclosed_indices.sort();

    let mut hidden_indices = (0..L).filter(|x| !disclosed_indices.contains(x)).collect::<Vec<usize>>();
    hidden_indices.sort();

    let disclosed_msg = (0..L)
        .filter(|x| disclosed_indices.contains(x))
        .map(|x| messages[x])
        .collect::<Vec<Scalar>>();
    let hidden_msg = (0..L)
        .filter(|x| hidden_indices.contains(x))
        .map(|x| messages[x])
        .collect::<Vec<Scalar>>();

    // get the signature parts
    let (A, e) = (signature.A, signature.e);

    // retrieve the BBS generators
    let generators = create_generators::<T>(L + 1);

    // TODO: use an arbitrary element for the el gamal generator. Currently the group generator is
    // used
    let elgamal_generator = G1Projective::generator();

    // sample the "domain" scalar
    // TODO: maybe add the elgamal_generator?
    let domain = calculate_domain::<T>(pk_bbs, &generators, header);

    // Generators for disclosed and hidden messages
    let H = generators.H;
    // Generators corresponding to secret messages
    let hidden_H = (0..L).filter(|x| hidden_indices.contains(x)).map(|x| H[x]).collect::<Vec<_>>();
    // Generators corresponding to disclosed messages
    let disclosed_H = (0..L).filter(|x| disclosed_indices.contains(x)).map(|x| H[x]).collect::<Vec<_>>();

    // sample random scalars
    // We need:
    //     - 3+U scalars for the blind signature (r, alpha, beta, delta_1, ...,delta_U
    //     - 1 scalar per el gamal ciphertext (gamma_i, ..., gamma_E)
    let scalars = calculate_random_scalars(3 + E + U);
    let r = scalars[0]; // blinds A, B, (C1, C2)
    let alpha = scalars[1];
    let beta = scalars[2];
    let mut gamma = Vec::with_capacity(E);
    for scalar in scalars.iter().skip(3).take(E) {
        gamma.push(*scalar);
    }

    let mut delta = Vec::with_capacity(U);

    // merge deltas with the corresponding index to later filter the deltas corresponding to
    // encrypted messages
    for (scalar, idx) in scalars.iter().skip(E + 3).take(U).zip(hidden_indices) {
        delta.push((*scalar, idx));
    }

    // delta subset corresponding to encrypted messages
    let delta_subset = delta.iter().filter(|(_, idx)| encrypted_indices.contains(idx)).collect::<Vec<_>>();

    // compute C_hidden, the commitment to the hidden messages:
    let C_hidden = hidden_H
        .iter()
        .zip(hidden_msg.iter())
        .fold(G1Projective::identity(), |acc, (g, m)| acc + g * m);

    // compute C_disclosed, the part computable by public input.
    // This corresponds to P1 + domain H0 + sum_{disclosed} m_i H_{i}:
    let C_disclosed = disclosed_H
        .iter()
        .zip(disclosed_msg.iter())
        .fold(generators.P1 + generators.Q1 * domain, |acc, (g, m)| acc + g * m);

    // Blind A with r
    let A_bar = A * r;

    // compute the B part of the signature
    let B_bar = (C_hidden + C_disclosed) * r - A_bar * e;

    // blinded ciphertexts mapping (C1i, C2i) -> (r C1i, r C2i)
    let C_bar = ciphertext.iter().map(|(C1, C2)| (r * C1, r * C2)).collect::<Vec<_>>();

    // Calculate U = alpha C_disclosed + beta A_bar + sum_{hidden} delta_i H_{i}
    let U = alpha * C_disclosed
        + beta * A_bar
        + hidden_H
            .iter()
            .zip(delta.iter())
            .fold(G1Projective::identity(), |acc, (h, delta)| acc + h * delta.0);

    // calculate U1 and U2 for proving correct computation of C_bar
    let U1 = ciphertext.iter().map(|&(C1, _)| alpha * C1).collect::<Vec<_>>();
    let U2 = ciphertext.iter().map(|&(_, C2)| alpha * C2).collect::<Vec<_>>();

    // calculate V1 and V2 for correctness of (elevated) encryption
    let V1 = gamma.iter().map(|gamma| gamma * elgamal_generator).collect::<Vec<_>>();
    let V2 = gamma
        .iter()
        .zip(delta_subset.iter())
        .map(|(gamma, delta)| gamma * pk_elgamal + delta.0 * elgamal_generator)
        .collect::<Vec<_>>();

    // calculate the FS challenge
    let rho = calculate_challenge_with_encryption::<T>(
        &A_bar,
        &B_bar,
        &C_bar,
        &U,
        &U1,
        &U2,
        &V1,
        &V2,
        &disclosed_indices,
        &disclosed_msg,
        &domain,
        ph,
    );

    // calculate s
    let s = alpha + rho * r;

    // calculate t
    let t = beta - rho * e;

    // calculate u
    let u = gamma
        .iter()
        .zip(c_randomness.iter())
        .map(|(gamma, r_eg)| gamma + rho * (r * r_eg))
        .collect::<Vec<_>>();

    // calculate v
    let v = delta.iter().zip(hidden_msg).map(|(delta, m)| delta.0 + rho * (r * m)).collect::<Vec<_>>();

    // 18. proof = (Abar, Bbar, c, r2^, r3^, (m^_j1, ..., m^_jU))
    //
    ProofWithEncrypted {
        A_bar,
        B_bar,
        C_bar,
        U,
        U1,
        U2,
        V1,
        V2,
        s,
        t,
        u,
        v,
        rho,
    }
}

// TODO: docs
#[allow(clippy::too_many_arguments)]
pub(crate) fn proof_with_enc_verify_impl<'a, T: BbsCiphersuite<'a>>(
    pk_bbs: &G2Projective,
    pk_elgamal: &G1Projective,
    ciphertext: &[(G1Projective, G1Projective)],
    proof: &ProofWithEncrypted,
    header: &[u8],
    ph: &[u8],
    disclosed_messages: &[Scalar],
    disclosed_indices: &[usize],
    encrypted_indices: &[usize],
) -> bool {
    // disclosed attributes length
    let R = disclosed_indices.len();

    // encrypted attributes length
    let E = encrypted_indices.len();

    // undisclosed attributes length
    let U = proof.v.len();

    // total length
    let L = R + U;

    // Assert indices are correct
    // 1. indices \in [0..L]
    if disclosed_indices.iter().any(|&i| i >= L) {
        return false;
    };
    if encrypted_indices.iter().any(|&i| i >= L) {
        return false;
    };
    // 2. encrypted indices and disclosed indices do not overlap
    if encrypted_indices.iter().any(|i| disclosed_indices.contains(i)) {
        return false;
    };

    // create vectors of disclosed/encrypted indices
    let mut disclosed_indices = disclosed_indices.to_vec();
    disclosed_indices.sort();
    // assert the disclosed indices size corresponds to the disclosed messages size
    if disclosed_indices.len() != R {
        return false;
    }

    let mut encrypted_indices = encrypted_indices.to_vec();
    encrypted_indices.sort();
    // assert the encrypted indices size corresponds to the ciphertext size
    if ciphertext.len() != E {
        return false;
    }

    let mut hidden_indices = (0..L).filter(|x| !disclosed_indices.contains(x)).collect::<Vec<usize>>();
    hidden_indices.sort();
    if hidden_indices.len() != U {
        return false;
    }

    // create the BBS generators
    let generators = create_generators::<T>(L + 1);

    // calculate the domain
    let domain = calculate_domain::<T>(pk_bbs, &generators, header);

    let H = generators.H;
    // get the generators for the hidden and disclosed messages
    let hidden_H = (0..L).filter(|x| hidden_indices.contains(x)).map(|x| H[x]).collect::<Vec<_>>();
    let disclosed_H = (0..L).filter(|x| disclosed_indices.contains(x)).map(|x| H[x]).collect::<Vec<_>>();

    // calculate the FS challenge
    let rho = calculate_challenge_with_encryption::<T>(
        &proof.A_bar,
        &proof.B_bar,
        &proof.C_bar,
        &proof.U,
        &proof.U1,
        &proof.U2,
        &proof.V1,
        &proof.V2,
        &disclosed_indices,
        disclosed_messages,
        &domain,
        ph,
    );
    // assert correct computation of rho FS challenge
    if rho != proof.rho {
        return false;
    }

    // =========== verify equation 1 =================
    let A_bar = proof.A_bar;
    let B_bar = proof.B_bar;
    let U = proof.U;
    let s = proof.s;
    let t = proof.t;
    let v = &proof.v;
    // assert correct size of v
    if v.len() != hidden_indices.len() {
        return false;
    }
    let indexed_v = v.iter().zip(hidden_indices.iter());

    // compute C_disclosed, the part computable by public input:
    let C_disclosed = disclosed_H
        .iter()
        .zip(disclosed_messages.iter())
        .fold(generators.P1 + generators.Q1 * domain, |acc, (g, m)| acc + g * m);
    let msm1 =
        U + rho * B_bar - (s * C_disclosed + t * A_bar + hidden_H.iter().zip(v.iter()).fold(G1Projective::identity(), |acc, (g, v)| acc + g * v));
    if msm1 != G1Projective::identity() {
        return false;
    }

    // =========== verify equation 3,4 =================
    let C_bar = &proof.C_bar;
    if C_bar.len() != E {
        return false;
    }
    let U1 = &proof.U1;
    if U1.len() != E {
        return false;
    }
    let U2 = &proof.U2;
    if U2.len() != E {
        return false;
    }
    let msm2 = ciphertext
        .iter()
        .zip(C_bar.iter())
        .zip(U1.iter())
        .map(|(((C1, _), (C_bar1, _)), U1)| s * C1 - (U1 + rho * C_bar1));
    let msm3 = ciphertext
        .iter()
        .zip(C_bar.iter())
        .zip(U2.iter())
        .map(|(((_, C2), (_, C_bar2)), U2)| s * C2 - (U2 + rho * C_bar2));
    if msm2.chain(msm3).any(|x| x != G1Projective::identity()) {
        return false;
    }

    // =========== verify equations 4,5 =================
    let V1 = &proof.V1;
    if V1.len() != E {
        return false;
    }
    let V2 = &proof.V2;
    if V2.len() != E {
        return false;
    }
    let u = &proof.u;
    if u.len() != E {
        return false;
    }

    let msm4 = C_bar
        .iter()
        .zip(V1.iter())
        .zip(u.iter())
        .map(|(((C1, _), V1), u)| V1 + rho * C1 - u * G1Projective::generator());
    let v_subset = indexed_v
        .filter(|(_, idx)| encrypted_indices.contains(idx))
        .map(|(v, _)| *v)
        .collect::<Vec<_>>();
    // let v_subset = encrypted_indices.iter().map(|&x| v[x-R]).collect::<Vec<_>>();
    let msm5 = C_bar
        .iter()
        .zip(V2.iter())
        .zip(u.iter())
        .zip(v_subset.iter())
        .map(|((((_, C2), V2), u), v)| V2 + rho * C2 - (u * pk_elgamal + v * G1Projective::generator()));
    if msm4.chain(msm5).any(|x| x != G1Projective::identity()) {
        return false;
    }

    // 12. if e(Abar, W) * e(Bbar, -P2) != Identity_GT, return INVALID
    multi_miller_loop(&[
        (&G1Affine::from(proof.A_bar), &G2Prepared::from(G2Affine::from(pk_bbs))),
        (&G1Affine::from(proof.B_bar), &G2Prepared::from(-G2Affine::generator())),
    ])
    .final_exponentiation()
        == Gt::identity()
}

fn calculate_random_scalars(count: usize) -> Vec<Scalar> {
    let mut scalars = vec![Scalar::zero(); count];
    for scalar in scalars.iter_mut() {
        let mut buffer = [0u8; 64];
        thread_rng().fill(&mut buffer);
        *scalar = Scalar::from_okm(buffer[0..POINT_LEN].try_into().unwrap())
    }
    scalars
}

impl ProofWithEncrypted {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        let ciphertext_len = (self.C_bar.len() as u64).to_le_bytes();
        result.push(&ciphertext_len[..]);

        let mut g_bytes = Vec::new();

        g_bytes.push(G1Affine::from(self.A_bar).to_compressed());
        g_bytes.push(G1Affine::from(self.B_bar).to_compressed());

        for (c0, c1) in &self.C_bar {
            g_bytes.push(G1Affine::from(c0).to_compressed());
            g_bytes.push(G1Affine::from(c1).to_compressed());
        }
        g_bytes.push(G1Affine::from(self.U).to_compressed());

        for g in &self.U1 {
            g_bytes.push(G1Affine::from(g).to_compressed());
        }
        for g in &self.U2 {
            g_bytes.push(G1Affine::from(g).to_compressed());
        }
        for g in &self.V1 {
            g_bytes.push(G1Affine::from(g).to_compressed());
        }
        for g in &self.V2 {
            g_bytes.push(G1Affine::from(g).to_compressed());
        }
        g_bytes.iter().for_each(|x| result.push(&x[..]));

        let mut s_bytes = Vec::new();

        s_bytes.push(self.s.i2osp(SCALAR_LEN));
        s_bytes.push(self.t.i2osp(SCALAR_LEN));

        for u in self.u.clone() {
            s_bytes.push(u.i2osp(SCALAR_LEN));
        }
        for v in self.v.clone() {
            s_bytes.push(v.i2osp(SCALAR_LEN));
        }
        s_bytes.push(self.rho.i2osp(SCALAR_LEN));

        s_bytes.iter().for_each(|x| result.push(&x[..]));

        result.concat()
    }

    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Error> {
        const P: usize = POINT_LEN;
        const S: usize = SCALAR_LEN;
        const U64: usize = mem::size_of::<u64>();

        let mut bytes = bytes.as_ref();

        let first_bytes: [u8; U64] = bytes[0..U64].try_into()?;
        let ciphertext_len = usize::from_le_bytes(first_bytes);
        bytes = &bytes[U64..];

        // courtesy of github copilot
        let A_bar = G1Affine::from_compressed(&<[u8; P]>::try_from(&bytes[..P])?)
            .map(G1Projective::from)
            .unwrap();
        let B_bar = G1Affine::from_compressed(&<[u8; P]>::try_from(&bytes[P..2 * P])?)
            .map(G1Projective::from)
            .unwrap();
        bytes = &bytes[2 * P..];

        let mut C_bar = Vec::with_capacity(ciphertext_len);
        for _ in 0..ciphertext_len {
            let c0 = G1Affine::from_compressed(&<[u8; P]>::try_from(&bytes[..P])?)
                .map(G1Projective::from)
                .unwrap();
            let c1 = G1Affine::from_compressed(&<[u8; P]>::try_from(&bytes[P..2 * P])?)
                .map(G1Projective::from)
                .unwrap();
            C_bar.push((c0, c1));
            bytes = &bytes[2 * P..];
        }

        let U = G1Affine::from_compressed(&<[u8; P]>::try_from(&bytes[..P])?)
            .map(G1Projective::from)
            .unwrap();
        bytes = &bytes[P..];

        let mut U1 = Vec::with_capacity(ciphertext_len);
        for _ in 0..ciphertext_len {
            let u = G1Affine::from_compressed(&<[u8; P]>::try_from(&bytes[..P])?)
                .map(G1Projective::from)
                .unwrap();
            U1.push(u);
            bytes = &bytes[P..];
        }
        let mut U2 = Vec::with_capacity(ciphertext_len);
        for _ in 0..ciphertext_len {
            let u = G1Affine::from_compressed(&<[u8; P]>::try_from(&bytes[..P])?)
                .map(G1Projective::from)
                .unwrap();
            U2.push(u);
            bytes = &bytes[P..];
        }
        let mut V1 = Vec::with_capacity(ciphertext_len);
        for _ in 0..ciphertext_len {
            let u = G1Affine::from_compressed(&<[u8; P]>::try_from(&bytes[..P])?)
                .map(G1Projective::from)
                .unwrap();
            V1.push(u);
            bytes = &bytes[P..];
        }
        let mut V2 = Vec::with_capacity(ciphertext_len);
        for _ in 0..ciphertext_len {
            let u = G1Affine::from_compressed(&<[u8; P]>::try_from(&bytes[..P])?)
                .map(G1Projective::from)
                .unwrap();
            V2.push(u);
            bytes = &bytes[P..];
        }

        let s = Scalar::os2ip(&bytes[..S]);
        bytes = &bytes[S..];

        let t = Scalar::os2ip(&bytes[..S]);
        bytes = &bytes[S..];

        let mut u = Vec::with_capacity(ciphertext_len);
        for _ in 0..ciphertext_len {
            let scalar = Scalar::os2ip(&bytes[..S]);
            u.push(scalar);
            bytes = &bytes[S..];
        }
        let mut v = Vec::with_capacity(ciphertext_len);

        let remaining_scalars = bytes.len() / S;

        for _ in 0..remaining_scalars - 1 {
            let scalar = Scalar::os2ip(&bytes[..S]);
            v.push(scalar);
            bytes = &bytes[S..];
        }

        let rho = Scalar::os2ip(&bytes[..S]);

        Ok(ProofWithEncrypted {
            A_bar,
            B_bar,
            C_bar,
            U,
            U1,
            U2,
            V1,
            V2,
            s,
            t,
            u,
            v,
            rho,
        })
    }
}

impl Debug for ProofWithEncrypted {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let tmp = self.to_bytes();
        write!(f, "0x")?;
        for &b in tmp.iter() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl Display for ProofWithEncrypted {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
