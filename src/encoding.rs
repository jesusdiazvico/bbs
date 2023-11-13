use std::fmt::{Debug, Display, Formatter, Result};

use bls12_381::{G1Projective, Scalar};

#[derive(Clone, PartialEq, Eq, Copy)]
pub struct Message(pub Scalar);

impl Debug for Message {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{:?}", self.0)
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{:?}", self.0)
    }
}

#[derive(Clone, PartialEq, Eq, Copy)]
pub struct Ciphertext(pub G1Projective, pub G1Projective);

impl Debug for Ciphertext {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "(\n\t{:?}, \n\t{:?}\n)", self.0, self.1)
    }
}

impl Display for Ciphertext {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "(\n\t{:?}, \n\t{:?}\n)", self.0, self.1)
    }
}

#[derive(Clone, PartialEq, Eq, Copy)]
pub struct EGPublikKey(pub G1Projective);

impl Debug for EGPublikKey {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{:?}", self.0)
    }
}

impl Display for EGPublikKey {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{:?}", self.0)
    }
}

#[derive(Clone, PartialEq, Eq, Copy)]
pub struct EGSecretKey(pub Scalar);

impl Debug for EGSecretKey {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{:?}", self.0)
    }
}

impl Display for EGSecretKey {
    fn fmt(&self, f: &mut Formatter) -> Result {
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
