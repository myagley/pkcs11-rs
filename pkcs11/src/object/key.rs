use std::default::Default;

use pkcs11_sys::*;

use crate::object::{Attribute, AttributeValue, ObjectClass, Template};

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
    fn from(key_type: KeyType) -> CK_KEY_TYPE {
        match key_type {
            KeyType::Acti => CK_KEY_TYPE::from(CKK_ACTI),
            KeyType::Aes => CK_KEY_TYPE::from(CKK_AES),
            KeyType::Aria => CK_KEY_TYPE::from(CKK_ARIA),
            KeyType::Baton => CK_KEY_TYPE::from(CKK_BATON),
            KeyType::Blowfish => CK_KEY_TYPE::from(CKK_BLOWFISH),
            KeyType::Camellia => CK_KEY_TYPE::from(CKK_CAMELLIA),
            KeyType::Cast => CK_KEY_TYPE::from(CKK_CAST),
            KeyType::Cast3 => CK_KEY_TYPE::from(CKK_CAST3),
            KeyType::Cast5 => CK_KEY_TYPE::from(CKK_CAST5),
            KeyType::Cast128 => CK_KEY_TYPE::from(CKK_CAST128),
            KeyType::Cdmf => CK_KEY_TYPE::from(CKK_CDMF),
            KeyType::Des => CK_KEY_TYPE::from(CKK_DES),
            KeyType::Des2 => CK_KEY_TYPE::from(CKK_DES2),
            KeyType::Des3 => CK_KEY_TYPE::from(CKK_DES3),
            KeyType::Dh => CK_KEY_TYPE::from(CKK_DH),
            KeyType::Dsa => CK_KEY_TYPE::from(CKK_DSA),
            KeyType::Ec => CK_KEY_TYPE::from(CKK_EC),
            KeyType::Ecdsa => CK_KEY_TYPE::from(CKK_ECDSA),
            KeyType::GenericSecret => CK_KEY_TYPE::from(CKK_GENERIC_SECRET),
            KeyType::Gost28147 => CK_KEY_TYPE::from(CKK_GOST28147),
            KeyType::Gostr3410 => CK_KEY_TYPE::from(CKK_GOSTR3410),
            KeyType::Gostr3411 => CK_KEY_TYPE::from(CKK_GOSTR3411),
            KeyType::Hotp => CK_KEY_TYPE::from(CKK_HOTP),
            KeyType::Idea => CK_KEY_TYPE::from(CKK_IDEA),
            KeyType::Juniper => CK_KEY_TYPE::from(CKK_JUNIPER),
            KeyType::Kea => CK_KEY_TYPE::from(CKK_KEA),
            KeyType::Md5Hmac => CK_KEY_TYPE::from(CKK_MD5_HMAC),
            KeyType::Rc2 => CK_KEY_TYPE::from(CKK_RC2),
            KeyType::Rc4 => CK_KEY_TYPE::from(CKK_RC4),
            KeyType::Rc5 => CK_KEY_TYPE::from(CKK_RC5),
            KeyType::Ripemd128Hmac => CK_KEY_TYPE::from(CKK_RIPEMD128_HMAC),
            KeyType::Ripemd160Hmac => CK_KEY_TYPE::from(CKK_RIPEMD160_HMAC),
            KeyType::Rsa => CK_KEY_TYPE::from(CKK_RSA),
            KeyType::Securid => CK_KEY_TYPE::from(CKK_SECURID),
            KeyType::Seed => CK_KEY_TYPE::from(CKK_SEED),
            KeyType::Sha224Hmac => CK_KEY_TYPE::from(CKK_SHA224_HMAC),
            KeyType::Sha256Hmac => CK_KEY_TYPE::from(CKK_SHA256_HMAC),
            KeyType::Sha384Hmac => CK_KEY_TYPE::from(CKK_SHA384_HMAC),
            KeyType::Sha512Hmac => CK_KEY_TYPE::from(CKK_SHA512_HMAC),
            KeyType::Sha1Hmac => CK_KEY_TYPE::from(CKK_SHA_1_HMAC),
            KeyType::Skipjack => CK_KEY_TYPE::from(CKK_SKIPJACK),
            KeyType::Twofish => CK_KEY_TYPE::from(CKK_TWOFISH),
            KeyType::Vendor => CK_KEY_TYPE::from(CKK_VENDOR_DEFINED),
            KeyType::X9_42Dh => CK_KEY_TYPE::from(CKK_X9_42_DH),
        }
    }
}

pub struct PublicKeyTemplate {
    attributes: Vec<Attribute>,
}

impl PublicKeyTemplate {
    pub fn new() -> Self {
        let attribute = Attribute::new(
            CKA_CLASS.into(),
            AttributeValue::ObjectClass(ObjectClass::PublicKey.into()),
        );
        let attributes = vec![attribute];
        Self { attributes }
    }

    pub fn key_type(&mut self, key_type: KeyType) -> &mut Self {
        let attribute = Attribute::new(
            CKA_KEY_TYPE.into(),
            AttributeValue::KeyType(key_type.into()),
        );
        self.attributes.push(attribute);
        self
    }

    // Common attributes
    attr_bool!(token_object, CKA_TOKEN);
    attr_bool!(private, CKA_PRIVATE);
    attr_bool!(modifiable, CKA_MODIFIABLE);
    attr_string!(label, CKA_LABEL);
    attr_bool!(copyable, CKA_COPYABLE);
    attr_bool!(destroyable, CKA_DESTROYABLE);

    // Common key attributes
    attr_bytes!(id, CKA_ID);
    // attr_date!(start_date, CKA_START_DATE);
    // attr_date!(end_date, CKA_END_DATE);
    attr_bool!(can_derive, CKA_DERIVE);
    attr_bool!(local, CKA_LOCAL);
    attr_mech!(keygen_mechanism, CKA_KEY_GEN_MECHANISM);
    //attr_mech_array!(allowed_mechanisms, CKA_ALLOWED_MECHANISMS);
    attr_bytes!(value, CKA_VALUE);

    // Public key attributes
    attr_bytes!(subject, CKA_SUBJECT);
    attr_bool!(can_encrypt, CKA_ENCRYPT);
    attr_bool!(can_verify, CKA_VERIFY);
    attr_bool!(can_verify_recover, CKA_VERIFY_RECOVER);
    attr_bool!(can_wrap, CKA_WRAP);
    attr_bool!(trusted, CKA_TRUSTED);
    //attr_attr_array!(wrap_template, CKA_WRAP_TEMPLATE);
    attr_bytes!(public_key_info, CKA_PUBLIC_KEY_INFO);
}

impl Default for PublicKeyTemplate {
    fn default() -> Self {
        PublicKeyTemplate::new()
    }
}

impl Template for PublicKeyTemplate {
    fn attributes(&self) -> &[Attribute] {
        &self.attributes
    }
}

pub struct PrivateKeyTemplate {
    attributes: Vec<Attribute>,
}

impl PrivateKeyTemplate {
    pub fn new() -> Self {
        let attribute = Attribute::new(
            CKA_CLASS.into(),
            AttributeValue::ObjectClass(ObjectClass::PrivateKey.into()),
        );
        let attributes = vec![attribute];
        Self { attributes }
    }

    pub fn key_type(&mut self, key_type: KeyType) -> &mut Self {
        let attribute = Attribute::new(
            CKA_KEY_TYPE.into(),
            AttributeValue::KeyType(key_type.into()),
        );
        self.attributes.push(attribute);
        self
    }

    // Common attributes
    attr_bool!(token_object, CKA_TOKEN);
    attr_bool!(private, CKA_PRIVATE);
    attr_bool!(modifiable, CKA_MODIFIABLE);
    attr_string!(label, CKA_LABEL);
    attr_bool!(copyable, CKA_COPYABLE);
    attr_bool!(destroyable, CKA_DESTROYABLE);

    // Common key attributes
    attr_bytes!(id, CKA_ID);
    // attr_date!(start_date, CKA_START_DATE);
    // attr_date!(end_date, CKA_END_DATE);
    attr_bool!(can_derive, CKA_DERIVE);
    attr_bool!(local, CKA_LOCAL);
    attr_mech!(keygen_mechanism, CKA_KEY_GEN_MECHANISM);
    //attr_mech_array!(allowed_mechanisms, CKA_ALLOWED_MECHANISMS);
    attr_bytes!(value, CKA_VALUE);

    // Private key attributes
    attr_bytes!(subject, CKA_SUBJECT);
    attr_bool!(sensitive, CKA_SENSITIVE);
    attr_bool!(can_decrypt, CKA_DECRYPT);
    attr_bool!(can_sign, CKA_SIGN);
    attr_bool!(can_sign_recover, CKA_SIGN_RECOVER);
    attr_bool!(can_unwrap, CKA_UNWRAP);
    attr_bool!(extractable, CKA_EXTRACTABLE);
    attr_bool!(always_sensitive, CKA_ALWAYS_SENSITIVE);
    attr_bool!(never_extractable, CKA_NEVER_EXTRACTABLE);
    attr_bool!(only_wrap_with_trusted, CKA_WRAP_WITH_TRUSTED);
    //attr_attr_array!(unwrap_template, CKA_UNWRAP_TEMPLATE);
    attr_bool!(alway_authenticate, CKA_ALWAYS_AUTHENTICATE);
    attr_bytes!(public_key_info, CKA_PUBLIC_KEY_INFO);
}

impl Default for PrivateKeyTemplate {
    fn default() -> Self {
        PrivateKeyTemplate::new()
    }
}

impl Template for PrivateKeyTemplate {
    fn attributes(&self) -> &[Attribute] {
        &self.attributes
    }
}

pub struct RsaPrivateKeyTemplate {
    attributes: Vec<Attribute>,
}

impl RsaPrivateKeyTemplate {
    pub fn new() -> Self {
        let object_class = Attribute::new(
            CKA_CLASS.into(),
            AttributeValue::ObjectClass(ObjectClass::PrivateKey.into()),
        );
        let key_type = Attribute::new(
            CKA_KEY_TYPE.into(),
            AttributeValue::KeyType(KeyType::Rsa.into()),
        );
        let attributes = vec![object_class, key_type];
        Self { attributes }
    }

    // Common attributes
    attr_bool!(token_object, CKA_TOKEN);
    attr_bool!(private, CKA_PRIVATE);
    attr_bool!(modifiable, CKA_MODIFIABLE);
    attr_string!(label, CKA_LABEL);
    attr_bool!(copyable, CKA_COPYABLE);
    attr_bool!(destroyable, CKA_DESTROYABLE);

    // Common key attributes
    attr_bytes!(id, CKA_ID);
    // attr_date!(start_date, CKA_START_DATE);
    // attr_date!(end_date, CKA_END_DATE);
    attr_bool!(can_derive, CKA_DERIVE);
    attr_bool!(local, CKA_LOCAL);
    attr_mech!(keygen_mechanism, CKA_KEY_GEN_MECHANISM);
    //attr_mech_array!(allowed_mechanisms, CKA_ALLOWED_MECHANISMS);

    // Private key attributes
    attr_bytes!(subject, CKA_SUBJECT);
    attr_bool!(sensitive, CKA_SENSITIVE);
    attr_bool!(can_decrypt, CKA_DECRYPT);
    attr_bool!(can_sign, CKA_SIGN);
    attr_bool!(can_sign_recover, CKA_SIGN_RECOVER);
    attr_bool!(can_unwrap, CKA_UNWRAP);
    attr_bool!(extractable, CKA_EXTRACTABLE);
    attr_bool!(always_sensitive, CKA_ALWAYS_SENSITIVE);
    attr_bool!(never_extractable, CKA_NEVER_EXTRACTABLE);
    attr_bool!(only_wrap_with_trusted, CKA_WRAP_WITH_TRUSTED);
    //attr_attr_array!(unwrap_template, CKA_UNWRAP_TEMPLATE);
    attr_bool!(alway_authenticate, CKA_ALWAYS_AUTHENTICATE);
    attr_bytes!(public_key_info, CKA_PUBLIC_KEY_INFO);

    // RSA private key attributes
    attr_bigint!(modulus, CKA_MODULUS);
    attr_bigint!(public_exponent, CKA_PUBLIC_EXPONENT);
    attr_bigint!(private_exponent, CKA_PRIVATE_EXPONENT);
    attr_bigint!(prime1, CKA_PRIME_1);
    attr_bigint!(prime2, CKA_PRIME_2);
    attr_bigint!(exponent1, CKA_EXPONENT_1);
    attr_bigint!(exponent2, CKA_EXPONENT_2);
    attr_bigint!(coefficient, CKA_COEFFICIENT);
}

impl Default for RsaPrivateKeyTemplate {
    fn default() -> Self {
        RsaPrivateKeyTemplate::new()
    }
}

impl Template for RsaPrivateKeyTemplate {
    fn attributes(&self) -> &[Attribute] {
        &self.attributes
    }
}

pub struct SecretKeyTemplate {
    attributes: Vec<Attribute>,
}

impl SecretKeyTemplate {
    pub fn new() -> Self {
        let attribute = Attribute::new(
            CKA_CLASS.into(),
            AttributeValue::ObjectClass(ObjectClass::SecretKey.into()),
        );
        let attributes = vec![attribute];
        Self { attributes }
    }

    pub fn key_type(&mut self, key_type: KeyType) -> &mut Self {
        let attribute = Attribute::new(
            CKA_KEY_TYPE.into(),
            AttributeValue::KeyType(key_type.into()),
        );
        self.attributes.push(attribute);
        self
    }

    // Common attributes
    attr_bool!(token_object, CKA_TOKEN);
    attr_bool!(private, CKA_PRIVATE);
    attr_bool!(modifiable, CKA_MODIFIABLE);
    attr_string!(label, CKA_LABEL);
    attr_bool!(copyable, CKA_COPYABLE);
    attr_bool!(destroyable, CKA_DESTROYABLE);

    // Common key attributes
    attr_bytes!(id, CKA_ID);
    // attr_date!(start_date, CKA_START_DATE);
    // attr_date!(end_date, CKA_END_DATE);
    attr_bool!(can_derive, CKA_DERIVE);
    attr_bool!(local, CKA_LOCAL);
    attr_mech!(keygen_mechanism, CKA_KEY_GEN_MECHANISM);
    //attr_mech_array!(allowed_mechanisms, CKA_ALLOWED_MECHANISMS);
    attr_bytes!(value, CKA_VALUE);

    // Secret key attributes
    attr_bool!(sensitive, CKA_SENSITIVE);
    attr_bool!(can_encrypt, CKA_ENCRYPT);
    attr_bool!(can_decrypt, CKA_DECRYPT);
    attr_bool!(can_sign, CKA_SIGN);
    attr_bool!(can_verify, CKA_VERIFY);
    attr_bool!(can_wrap, CKA_WRAP);
    attr_bool!(can_unwrap, CKA_UNWRAP);
    attr_bool!(extractable, CKA_EXTRACTABLE);
    attr_bool!(always_sensitive, CKA_ALWAYS_SENSITIVE);
    attr_bool!(never_extractable, CKA_NEVER_EXTRACTABLE);
    attr_bytes!(check_value, CKA_CHECK_VALUE);
    attr_bool!(only_wrap_with_trusted, CKA_WRAP_WITH_TRUSTED);
    attr_bool!(trusted, CKA_TRUSTED);
    //attr_attr_array!(wrap_template, CKA_WRAP_TEMPLATE);
    //attr_attr_array!(unwrap_template, CKA_UNWRAP_TEMPLATE);
}

impl Default for SecretKeyTemplate {
    fn default() -> Self {
        SecretKeyTemplate::new()
    }
}

impl Template for SecretKeyTemplate {
    fn attributes(&self) -> &[Attribute] {
        &self.attributes
    }
}
