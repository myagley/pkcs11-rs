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
        let attribute = Attribute::new(
            CKA_CLASS.into(),
            AttributeValue::ObjectClass(ObjectClass::PublicKey.into()),
        );
        let attributes = vec![attribute];
        Self { attributes }
    }

    pub fn key_type<'a>(&'a mut self, key_type: KeyType) -> &'a mut Self {
        let attribute = Attribute::new(
            CKA_KEY_TYPE.into(),
            AttributeValue::KeyType(key_type.into()),
        );
        self.attributes.push(attribute);
        self
    }

    // Common attributes
    attr_bool!(is_token_object, CKA_TOKEN);
    attr_bool!(is_private, CKA_PRIVATE);
    attr_bool!(is_modifiable, CKA_MODIFIABLE);
    attr_string!(label, CKA_LABEL);
    attr_bool!(is_copyable, CKA_COPYABLE);
    attr_bool!(is_destroyable, CKA_DESTROYABLE);

    // Common key attributes
    attr_bytes!(id, CKA_ID);
    // attr_date!(start_date, CKA_START_DATE);
    // attr_date!(end_date, CKA_END_DATE);
    attr_bool!(can_derive, CKA_DERIVE);
    attr_bool!(is_local, CKA_LOCAL);
    //attr_mech!(keygen_mechanism, CKA_KEY_GEN_MECHANISM);
    //attr_mech_array!(allowed_mechanisms, CKA_ALLOWED_MECHANISMS);
    attr_bytes!(value, CKA_VALUE);

    // Public key attributes
    attr_bytes!(subject, CKA_SUBJECT);
    attr_bool!(can_encrypt, CKA_ENCRYPT);
    attr_bool!(can_verify, CKA_VERIFY);
    attr_bool!(can_verify_recover, CKA_VERIFY_RECOVER);
    attr_bool!(can_wrap, CKA_WRAP);
    attr_bool!(is_trusted, CKA_TRUSTED);
    //attr_attr_array!(wrap_template, CKA_WRAP_TEMPLATE);
    attr_bytes!(public_key_info, CKA_PUBLIC_KEY_INFO);
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

    pub fn key_type<'a>(&'a mut self, key_type: KeyType) -> &'a mut Self {
        let attribute = Attribute::new(
            CKA_KEY_TYPE.into(),
            AttributeValue::KeyType(key_type.into()),
        );
        self.attributes.push(attribute);
        self
    }

    // Common attributes
    attr_bool!(is_token_object, CKA_TOKEN);
    attr_bool!(is_private, CKA_PRIVATE);
    attr_bool!(is_modifiable, CKA_MODIFIABLE);
    attr_string!(label, CKA_LABEL);
    attr_bool!(is_copyable, CKA_COPYABLE);
    attr_bool!(is_destroyable, CKA_DESTROYABLE);

    // Common key attributes
    attr_bytes!(id, CKA_ID);
    // attr_date!(start_date, CKA_START_DATE);
    // attr_date!(end_date, CKA_END_DATE);
    attr_bool!(can_derive, CKA_DERIVE);
    attr_bool!(is_local, CKA_LOCAL);
    //attr_mech!(keygen_mechanism, CKA_KEY_GEN_MECHANISM);
    //attr_mech_array!(allowed_mechanisms, CKA_ALLOWED_MECHANISMS);
    attr_bytes!(value, CKA_VALUE);

    // Private key attributes
    attr_bytes!(subject, CKA_SUBJECT);
    attr_bool!(is_sensitive, CKA_SENSITIVE);
    attr_bool!(can_decrypt, CKA_DECRYPT);
    attr_bool!(can_sign, CKA_SIGN);
    attr_bool!(can_sign_recover, CKA_SIGN_RECOVER);
    attr_bool!(can_unwrap, CKA_UNWRAP);
    attr_bool!(is_extractable, CKA_EXTRACTABLE);
    attr_bool!(always_sensitive, CKA_ALWAYS_SENSITIVE);
    attr_bool!(never_extractable, CKA_NEVER_EXTRACTABLE);
    attr_bool!(only_wrap_with_trusted, CKA_WRAP_WITH_TRUSTED);
    //attr_attr_array!(unwrap_template, CKA_UNWRAP_TEMPLATE);
    attr_bool!(alway_authenticate, CKA_ALWAYS_AUTHENTICATE);
    attr_bytes!(public_key_info, CKA_PUBLIC_KEY_INFO);
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

    pub fn key_type<'a>(&'a mut self, key_type: KeyType) -> &'a mut Self {
        let attribute = Attribute::new(
            CKA_KEY_TYPE.into(),
            AttributeValue::KeyType(key_type.into()),
        );
        self.attributes.push(attribute);
        self
    }

    // Common attributes
    attr_bool!(is_token_object, CKA_TOKEN);
    attr_bool!(is_private, CKA_PRIVATE);
    attr_bool!(is_modifiable, CKA_MODIFIABLE);
    attr_string!(label, CKA_LABEL);
    attr_bool!(is_copyable, CKA_COPYABLE);
    attr_bool!(is_destroyable, CKA_DESTROYABLE);

    // Common key attributes
    attr_bytes!(id, CKA_ID);
    // attr_date!(start_date, CKA_START_DATE);
    // attr_date!(end_date, CKA_END_DATE);
    attr_bool!(can_derive, CKA_DERIVE);
    attr_bool!(is_local, CKA_LOCAL);
    //attr_mech!(keygen_mechanism, CKA_KEY_GEN_MECHANISM);
    //attr_mech_array!(allowed_mechanisms, CKA_ALLOWED_MECHANISMS);
    attr_bytes!(value, CKA_VALUE);

    // Secret key attributes
    attr_bool!(is_sensitive, CKA_SENSITIVE);
    attr_bool!(can_encrypt, CKA_ENCRYPT);
    attr_bool!(can_decrypt, CKA_DECRYPT);
    attr_bool!(can_sign, CKA_SIGN);
    attr_bool!(can_verify, CKA_VERIFY);
    attr_bool!(can_wrap, CKA_WRAP);
    attr_bool!(can_unwrap, CKA_UNWRAP);
    attr_bool!(is_extractable, CKA_EXTRACTABLE);
    attr_bool!(always_sensitive, CKA_ALWAYS_SENSITIVE);
    attr_bool!(never_extractable, CKA_NEVER_EXTRACTABLE);
    attr_bytes!(check_value, CKA_CHECK_VALUE);
    attr_bool!(only_wrap_with_trusted, CKA_WRAP_WITH_TRUSTED);
    attr_bool!(is_trusted, CKA_TRUSTED);
    //attr_attr_array!(wrap_template, CKA_WRAP_TEMPLATE);
    //attr_attr_array!(unwrap_template, CKA_UNWRAP_TEMPLATE);
}

impl Template for SecretKeyTemplate {
    fn attributes(&self) -> &[Attribute] {
        &self.attributes
    }
}
