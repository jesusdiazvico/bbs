use bls12_381::{G1Projective, G2Projective, Scalar};
use itertools::Itertools;

use crate::{
    ciphersuite::BbsCiphersuite,
    encoding::I2OSP,
    generators::Generators,
    hashing::{hash_to_scalar, EncodeForHash},
};

pub(crate) fn calculate_domain<'a, T>(pk: &G2Projective, generators: &Generators, header: &[u8]) -> Scalar
where
    T: BbsCiphersuite<'a>,
{
    // 1.  L = length(H_Points)
    let L = generators.H.len();

    // 4.  dom_array = (L, Q_1, H_1, ..., H_L)
    let dom_array_serilized = [
        L.serialize(),
        generators.Q1.serialize(),
        generators.H.iter().map(|g| g.serialize()).concat(),
    ]
    .concat();

    // 5.  dom_octs = serialize(dom_array) || ciphersuite_id
    let dom_octs = [dom_array_serilized, T::CIPHERSUITE_ID.to_vec()].concat();

    // 7.  dom_input = PK || dom_octs || I2OSP(length(header), 8) || header
    let dom_input = [pk.serialize(), dom_octs, header.len().i2osp(8), header.to_vec()].concat();

    // 4.  domain = hash_to_scalar(dom_for_hash, 1)
    hash_to_scalar::<T>(&dom_input, &[])
}

pub(crate) fn calculate_challenge<'a, T>(
    A_bar: &G1Projective,
    B_bar: &G1Projective,
    T: &G1Projective,
    disclosed_indices: &[usize],
    disclosed_messages: &[Scalar],
    domain: &Scalar,
    ph: &[u8],
) -> Scalar
where
    T: BbsCiphersuite<'a>,
{
    let R = disclosed_indices.len();
    let c_array = [
        A_bar.serialize(),
        B_bar.serialize(),
        T.serialize(),
        R.serialize(),
        disclosed_indices.iter().map(|x| x.serialize()).concat(),
        disclosed_messages.iter().map(|x| x.serialize()).concat(),
        domain.serialize(),
    ];
    let c_octs = c_array.concat();
    let c_input = [c_octs, ph.len().i2osp(8), ph.to_vec()].concat();

    hash_to_scalar::<T>(&c_input, &[])
}

// TODO: Should check the FS transform is done correctly. For example, here statement is not
// hashed!
#[allow(clippy::too_many_arguments)]
pub(crate) fn calculate_challenge_with_encryption<'a, T>(
    A_bar: &G1Projective,
    B_bar: &G1Projective,
    C_bar: &[(G1Projective, G1Projective)],
    U: &G1Projective,
    U1: &[G1Projective],
    U2: &[G1Projective],
    V1: &[G1Projective],
    V2: &[G1Projective],
    disclosed_indices: &[usize],
    disclosed_messages: &[Scalar],
    domain: &Scalar,
    ph: &[u8],
) -> Scalar
where
    T: BbsCiphersuite<'a>,
{
    let c_array = [
        A_bar.serialize(),
        B_bar.serialize(),
        C_bar.iter().map(|(C1, C2)| [C1.serialize(), C2.serialize()].concat()).concat(),
        U.serialize(),
        U1.iter().map(|U| U.serialize()).concat(),
        U2.iter().map(|U| U.serialize()).concat(),
        V1.iter().map(|V| V.serialize()).concat(),
        V2.iter().map(|V| V.serialize()).concat(),
        disclosed_indices.iter().map(|x| x.serialize()).concat(),
        disclosed_messages.iter().map(|x| x.serialize()).concat(),
        domain.serialize(),
    ];
    let c_octs = c_array.concat();
    let c_input = [c_octs, ph.len().i2osp(8), ph.to_vec()].concat();

    hash_to_scalar::<T>(&c_input, &[])
}
