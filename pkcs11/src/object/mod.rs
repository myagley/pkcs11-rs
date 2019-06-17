use pkcs11_sys::*;

use crate::Session;

mod certificate;
mod hardware;
mod key;
mod mechanism;

pub use certificate::CertificateType;
pub use hardware::HwFeatureType;
pub use key::{KeyType, PublicKeyTemplate};
pub use mechanism::MechanismType;

/// A token-specific identifier for an object.
///
/// Object handles are tied to a session.
/// This handle is only valid for the particular session in use.
/// Hence, the reference to a session.
pub struct Object<'c, 's> {
    handle: CK_ULONG,
    session: &'s Session<'c>,
}

/// A value that identifies the classes (or types) of objects that Cryptoki
/// recognizes.
///
/// Object classes are defined with the objects that use them. The type is
/// specified on an object through the CKA_CLASS attribute of the object.
///
/// Vendor defined values for this type may also be specified.
pub enum ObjectClass {
    Certificate,
    Data,
    DomainParameters,
    HwFeature,
    OtpKey,
    PrivateKey,
    PublicKey,
    SecretKey,
    Vendor,
}

pub struct Attribute {
    key: CK_ATTRIBUTE_TYPE,
    value: AttributeValue,
}

impl Attribute {
    pub fn new(key: CK_ATTRIBUTE_TYPE, value: AttributeValue) -> Self {
        Attribute { key, value }
    }
}

pub enum AttributeValue {
    ObjectClass(ObjectClass),
    CertificateType(CertificateType),
    HwFeatureType(HwFeatureType),
    KeyType(KeyType),
    Bool(CK_BBOOL),
    Bytes(Vec<u8>),
    Num(CK_ULONG),
    String(String),
    Date(CK_DATE),
}

pub trait Template {
    fn attributes(&self) -> &[Attribute];
}
