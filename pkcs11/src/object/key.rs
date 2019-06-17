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
    X9_42Dh,
}

impl From<KeyType> for CK_KEY_TYPE {
    fn from(hw_feature_type: KeyType) -> CK_KEY_TYPE {
        match hw_feature_type {
            KeyType::Acti => CKK_ACTI as CK_KEY_TYPE,
            KeyType::Aes => CKK_AES as CK_KEY_TYPE,
            KeyType::Aria => CKK_ARIA as CK_KEY_TYPE,
            KeyType::Baton => CKK_BATON as CK_KEY_TYPE,
            KeyType::Blowfish => CKK_BLOWFISH as CK_KEY_TYPE,
            KeyType::Camellia => CKK_CAMELLIA as CK_KEY_TYPE,
            KeyType::Cast => CKK_CAST as CK_KEY_TYPE,
            KeyType::Cast3 => CKK_CAST3 as CK_KEY_TYPE,
            KeyType::Cast5 => CKK_CAST5 as CK_KEY_TYPE,
            KeyType::Cast128 => CKK_CAST128 as CK_KEY_TYPE,
            KeyType::Cdmf => CKK_CDMF as CK_KEY_TYPE,
            KeyType::Des => CKK_DES as CK_KEY_TYPE,
            KeyType::Des2 => CKK_DES2 as CK_KEY_TYPE,
            KeyType::Des3 => CKK_DES3 as CK_KEY_TYPE,
            KeyType::Dh => CKK_DH as CK_KEY_TYPE,
            KeyType::Dsa => CKK_DSA as CK_KEY_TYPE,
            KeyType::Ec => CKK_EC as CK_KEY_TYPE,
            KeyType::Ecdsa => CKK_ECDSA as CK_KEY_TYPE,
            KeyType::GenericSecret => CKK_GENERIC_SECRET as CK_KEY_TYPE,
            KeyType::Gost28147 => CKK_GOST28147 as CK_KEY_TYPE,
            KeyType::Gostr3410 => CKK_GOSTR3410 as CK_KEY_TYPE,
            KeyType::Gostr3411 => CKK_GOSTR3411 as CK_KEY_TYPE,
            KeyType::Hotp => CKK_HOTP as CK_KEY_TYPE,
            KeyType::Idea => CKK_IDEA as CK_KEY_TYPE,
            KeyType::Juniper => CKK_JUNIPER as CK_KEY_TYPE,
            KeyType::Kea => CKK_KEA as CK_KEY_TYPE,
            KeyType::Md5Hmac => CKK_MD5_HMAC as CK_KEY_TYPE,
            KeyType::Rc2 => CKK_RC2 as CK_KEY_TYPE,
            KeyType::Rc4 => CKK_RC4 as CK_KEY_TYPE,
            KeyType::Rc5 => CKK_RC5 as CK_KEY_TYPE,
            KeyType::Ripemd128Hmac => CKK_RIPEMD128_HMAC as CK_KEY_TYPE,
            KeyType::Ripemd160Hmac => CKK_RIPEMD160_HMAC as CK_KEY_TYPE,
            KeyType::Rsa => CKK_RSA as CK_KEY_TYPE,
            KeyType::Securid => CKK_SECURID as CK_KEY_TYPE,
            KeyType::Seed => CKK_SEED as CK_KEY_TYPE,
            KeyType::Sha224Hmac => CKK_SHA224_HMAC as CK_KEY_TYPE,
            KeyType::Sha256Hmac => CKK_SHA256_HMAC as CK_KEY_TYPE,
            KeyType::Sha384Hmac => CKK_SHA384_HMAC as CK_KEY_TYPE,
            KeyType::Sha512Hmac => CKK_SHA512_HMAC as CK_KEY_TYPE,
            KeyType::Sha1Hmac => CKK_SHA_1_HMAC as CK_KEY_TYPE,
            KeyType::Skipjack => CKK_SKIPJACK as CK_KEY_TYPE,
            KeyType::Twofish => CKK_TWOFISH as CK_KEY_TYPE,
            KeyType::Vendor => CKK_VENDOR_DEFINED as CK_KEY_TYPE,
            KeyType::X9_42Dh => CKK_X9_42_DH as CK_KEY_TYPE,
        }
    }
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
        let attribute = Attribute::new(
            CKA_KEY_TYPE as u64,
            AttributeValue::KeyType(key_type.into()),
        );
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
