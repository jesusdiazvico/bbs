use std::fmt::{Debug, Display, Formatter, Result as NullResult};

use bls12_381::{G1Projective, Scalar, G1Affine};
use serde::{Serialize, Deserialize, Deserializer};

#[derive(Clone, PartialEq, Eq, Copy)]
pub struct Message(pub Scalar);

impl Debug for Message {
    fn fmt(&self, f: &mut Formatter) -> NullResult {
        write!(f, "{:?}", self.0)
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter) -> NullResult {
        write!(f, "{:?}", self.0)
    }
}

#[derive(Clone, PartialEq, Eq, Copy)]
pub struct Ciphertext(pub G1Projective, pub G1Projective);

impl Debug for Ciphertext {
    fn fmt(&self, f: &mut Formatter) -> NullResult {
        write!(f, "(\n\t{:?}, \n\t{:?}\n)", self.0, self.1)
    }
}

impl Display for Ciphertext {
    fn fmt(&self, f: &mut Formatter) -> NullResult {
        write!(f, "(\n\t{:?}, \n\t{:?}\n)", self.0, self.1)
    }
}

#[derive(Clone, PartialEq, Eq, Copy)]
pub struct EGPublikKey(pub G1Projective);

impl Debug for EGPublikKey {
    fn fmt(&self, f: &mut Formatter) -> NullResult {
        write!(f, "{:?}", self.0)
    }
}

impl Display for EGPublikKey {
    fn fmt(&self, f: &mut Formatter) -> NullResult {
        write!(f, "{:?}", self.0)
    }
}

#[derive(Clone, PartialEq, Eq, Copy)]
pub struct EGSecretKey(pub Scalar);

impl Debug for EGSecretKey {
    fn fmt(&self, f: &mut Formatter) -> NullResult {
        write!(f, "{:?}", self.0)
    }
}

impl Display for EGSecretKey {
    fn fmt(&self, f: &mut Formatter) -> NullResult {
        write!(f, "{:?}", self.0)
    }
}

pub trait I2OSP {
    fn i2osp(&self, len: usize) -> Vec<u8>;
}

pub trait OS2IP {
    fn os2ip(buf: &[u8]) -> Self;
}

impl I2OSP for usize {
    fn i2osp(&self, len: usize) -> Vec<u8> {
        (*self as u64).i2osp(len)
    }
}

impl I2OSP for u8 {
    fn i2osp(&self, len: usize) -> Vec<u8> {
        (*self as u64).i2osp(len)
    }
}

impl I2OSP for u64 {
    fn i2osp(&self, len: usize) -> Vec<u8> {
        let i = self.to_be_bytes();
        if len > i.len() {
            let mut v = vec![0u8; len - i.len()];
            v.extend_from_slice(&i);
            v
        } else {
            i[i.len() - len..].to_vec()
        }
    }
}

impl I2OSP for Scalar {
    fn i2osp(&self, _: usize) -> Vec<u8> {
        let mut i = self.to_bytes();
        i.reverse();
        i.to_vec()
    }
}

impl OS2IP for Scalar {
    fn os2ip(buf: &[u8]) -> Self {
        let mut i = buf[..].to_vec();
        i.reverse();
        Scalar::from_bytes(i.as_slice().try_into().unwrap()).unwrap()
    }
}

impl EGPublikKey {
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Self {
        let bytes = bytes.as_ref();
        if bytes.len() != 48 {
            panic!("Invalid length");
        }
        let mut buf = [0u8; 48];
        buf.copy_from_slice(bytes);
        let g1 = G1Projective::from(G1Affine::from_compressed(&buf).unwrap());
        EGPublikKey(g1)
    }

    pub fn to_bytes(&self) -> [u8; 48] {
        G1Affine::from(self.0).to_compressed()
    }
}

impl Serialize for EGPublikKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for EGPublikKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(EGPublikKey::from_bytes(&bytes[..]))
    }
}

#[cfg(test)]
mod test {
    use crate::encoding::I2OSP;

    #[test]
    fn to_octet_string_test() {
        let i = 42usize;

        assert_eq!(i.i2osp(1), [42]);
        assert_eq!(i.i2osp(10), [0, 0, 0, 0, 0, 0, 0, 0, 0, 42]);
        assert_eq!(i.i2osp(3), vec![0, 0, 42]);
    }
}
