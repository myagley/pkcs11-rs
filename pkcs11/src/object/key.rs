use pkcs11_sys::*;

use crate::object::{Attribute, AttributeValue};

/// A value that identifies a key type.
///
/// Key types are defined with the objects and mechanisms that use them. The
/// key type is specified on an object through the CKA_KEY_TYPE attribute of
/// the object.
///
/// Vendor defined values for this type may also be specified.
#[derive(Debug, PartialEq)]
pub enum KeyType {
    Acti,
    Aes,
    Aria,
    Baton,
    Blowfish,
    Camellia,
    Cast,
    Cast3,
    Cast5,
    Cast128,
    Cdmf,
    Des,
    Des2,
    Des3,
    Dh,
    Dsa,
    Ec,
    Ecdsa,
    GenericSecret,
    Gost28147,
    Gostr3410,
    Gostr3411,
    Hotp,
    Idea,
    Juniper,
    Kea,
    Md5Hmac,
    Rc2,
    Rc4,
    Rc5,
    Ripemd128Hmac,
    Ripemd160Hmac,
    Rsa,
    Securid,
    Seed,
    Sha224Hmac,
    Sha256Hmac,
    Sha384Hmac,
    Sha512Hmac,
    Sha1Hmac,
    Skipjack,
    Twofish,
    Vendor,
    X942Dh,
}

pub struct PublicKeyTemplate {
    attributes: Vec<Attribute>,
}

impl PublicKeyTemplate {
    pub fn new() -> Self {
        Self {
            attributes: Vec::new(),
        }
    }

    pub fn key_type<'a>(&'a mut self, key_type: KeyType) -> &'a mut Self {
        let attribute = Attribute::new(CKA_KEY_TYPE as u64, AttributeValue::KeyType(key_type));
        self.attributes.push(attribute);
        self
    }

    pub fn id<'a>(&'a mut self, id: Vec<u8>) -> &'a mut Self {
        let attribute = Attribute::new(CKA_ID as u64, AttributeValue::Bytes(id));
        self.attributes.push(attribute);
        self
    }

    pub fn can_derive<'a>(&'a mut self, can_derive: bool) -> &'a mut Self {
        let value = if can_derive {
            AttributeValue::Bool(CK_TRUE as CK_BBOOL)
        } else {
            AttributeValue::Bool(CK_FALSE as CK_BBOOL)
        };
        let attribute = Attribute::new(CKA_DERIVE as u64, value);
        self.attributes.push(attribute);
        self
    }
}
