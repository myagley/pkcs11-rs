use std::ffi::c_void;
use std::mem;

pub use num_bigint::BigUint;
use pkcs11_sys::*;

use crate::session::Session;
use crate::Error;

/// A token-specific identifier for an object.
#[derive(Debug)]
pub struct Object {
    pub(crate) handle: CK_OBJECT_HANDLE,
    pub(crate) session: Session,
}

impl Object {
    pub fn sign<M>(&self, mechanism: M, data: &[u8]) -> Result<Vec<u8>, Error>
    where
        M: Mechanism,
    {
        self.session.sign(&self, mechanism, data)
    }

    pub fn verify<M>(&self, mechanism: M, data: &[u8], signature: &[u8]) -> Result<bool, Error>
    where
        M: Mechanism,
    {
        self.session.verify(&self, mechanism, data, signature)
    }
}

/// A value that identifies the classes (or types) of objects that Cryptoki
/// recognizes.
///
/// Object classes are defined with the objects that use them. The type is
/// specified on an object through the CKA_CLASS attribute of the object.
///
/// Vendor defined values for this type may also be specified.
pub(crate) enum ObjectClass {
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

impl From<ObjectClass> for CK_OBJECT_CLASS {
    fn from(object_class: ObjectClass) -> CK_OBJECT_CLASS {
        match object_class {
            ObjectClass::Certificate => CK_OBJECT_CLASS::from(CKO_CERTIFICATE),
            ObjectClass::Data => CK_OBJECT_CLASS::from(CKO_DATA),
            ObjectClass::DomainParameters => CK_OBJECT_CLASS::from(CKO_DOMAIN_PARAMETERS),
            ObjectClass::HwFeature => CK_OBJECT_CLASS::from(CKO_HW_FEATURE),
            ObjectClass::OtpKey => CK_OBJECT_CLASS::from(CKO_OTP_KEY),
            ObjectClass::PrivateKey => CK_OBJECT_CLASS::from(CKO_PRIVATE_KEY),
            ObjectClass::PublicKey => CK_OBJECT_CLASS::from(CKO_PUBLIC_KEY),
            ObjectClass::SecretKey => CK_OBJECT_CLASS::from(CKO_SECRET_KEY),
            ObjectClass::Vendor => CK_OBJECT_CLASS::from(CKO_VENDOR_DEFINED),
        }
    }
}

pub struct Attribute {
    key: CK_ATTRIBUTE_TYPE,
    value: AttributeValue,
}

impl Attribute {
    pub(crate) fn new(key: CK_ATTRIBUTE_TYPE, value: AttributeValue) -> Self {
        Attribute { key, value }
    }

    pub(crate) fn key(&self) -> CK_ATTRIBUTE_TYPE {
        self.key
    }

    pub(crate) fn value(&self) -> &AttributeValue {
        &self.value
    }
}

pub(crate) enum AttributeValue {
    ObjectClass(CK_OBJECT_CLASS),
    CertificateType(CK_CERTIFICATE_TYPE),
    // HwFeatureType(CK_HW_FEATURE_TYPE),
    KeyType(CK_KEY_TYPE),
    Bool(CK_BBOOL),
    Bytes(Vec<u8>),
    Num(BigUint),
    String(String),
    // Date(CK_DATE),
    MechanismType(CK_MECHANISM_TYPE),
}

impl AttributeValue {
    pub(crate) fn value(&self) -> *const c_void {
        match self {
            AttributeValue::ObjectClass(ref obj) => obj as *const _ as *const c_void,
            AttributeValue::CertificateType(ref cert) => cert as *const _ as *const c_void,
            // AttributeValue::HwFeatureType(ref feat) => feat as *const _ as *const c_void,
            AttributeValue::KeyType(ref key) => key as *const _ as *const c_void,
            AttributeValue::Bool(ref b) => b as *const _ as *const c_void,
            AttributeValue::Bytes(ref b) => b.as_ptr() as *const c_void,
            AttributeValue::Num(ref n) => n.to_bytes_be().as_ptr() as *const c_void,
            AttributeValue::String(ref s) => s.as_bytes() as *const _ as *const c_void,
            // AttributeValue::Date(ref d) => d as *const _ as *const c_void,
            AttributeValue::MechanismType(ref t) => t as *const _ as *const c_void,
        }
    }

    pub(crate) fn len(&self) -> CK_ULONG {
        match self {
            AttributeValue::ObjectClass(_) => mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
            AttributeValue::CertificateType(_) => mem::size_of::<CK_CERTIFICATE_TYPE>() as CK_ULONG,
            // AttributeValue::HwFeatureType(_) => mem::size_of::<CK_HW_FEATURE_TYPE>() as CK_ULONG,
            AttributeValue::KeyType(_) => mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
            AttributeValue::Bool(_) => mem::size_of::<CK_BBOOL>() as CK_ULONG,
            AttributeValue::Bytes(b) => b.len() as CK_ULONG,
            AttributeValue::Num(n) => n.to_bytes_be().len() as CK_ULONG,
            AttributeValue::String(s) => s.as_bytes().len() as CK_ULONG,
            // AttributeValue::Date(_) => mem::size_of::<CK_DATE>() as CK_ULONG,
            AttributeValue::MechanismType(_) => mem::size_of::<CK_MECHANISM_TYPE>() as CK_ULONG,
        }
    }
}

pub trait Template {
    fn attributes(&self) -> &[Attribute];
}

macro_rules! r#attr_bool {
    ($op:ident,$attr:ident) => {
        pub fn $op(&mut self, $op: bool) -> &mut Self {
            let value = if $op {
                $crate::object::AttributeValue::Bool(pkcs11_sys::CK_TRUE as pkcs11_sys::CK_BBOOL)
            } else {
                $crate::object::AttributeValue::Bool(pkcs11_sys::CK_FALSE as pkcs11_sys::CK_BBOOL)
            };
            let attribute = $crate::object::Attribute::new(pkcs11_sys::$attr.into(), value);
            self.attributes.push(attribute);
            self
        }
    }
}

macro_rules! r#attr_bigint {
    ($op:ident,$attr:ident) => {
        pub fn $op(&mut self, $op: $crate::object::BigUint) -> &mut Self {
            let attribute = $crate::object::Attribute::new(pkcs11_sys::$attr.into(), $crate::object::AttributeValue::Num($op));
            self.attributes.push(attribute);
            self
        }
    }
}

macro_rules! r#attr_bytes {
    ($op:ident,$attr:ident) => {
        pub fn $op(&mut self, $op: Vec<u8>) -> &mut Self {
            let attribute = $crate::object::Attribute::new(pkcs11_sys::$attr.into(), $crate::object::AttributeValue::Bytes($op));
            self.attributes.push(attribute);
            self
        }
    }
}

macro_rules! r#attr_mech {
    ($op:ident,$attr:ident) => {
        pub fn $op(&mut self, $op: $crate::object::MechanismType) -> &mut Self {
            let attribute = $crate::object::Attribute::new(pkcs11_sys::$attr.into(), $crate::object::AttributeValue::MechanismType($op.into()));
            self.attributes.push(attribute);
            self
        }
    }
}

macro_rules! r#attr_string {
    ($op:ident,$attr:ident) => {
        pub fn $op(&mut self, $op: String) -> &mut Self {
            let attribute = $crate::object::Attribute::new(pkcs11_sys::$attr.into(), $crate::object::AttributeValue::String($op));
            self.attributes.push(attribute);
            self
        }
    }
}

mod certificate;
mod hardware;
mod key;
mod mechanism;

pub use certificate::{CertificateType, X509CertificateTemplate};
pub use hardware::HwFeatureType;
pub use key::{
    KeyType, PrivateKeyTemplate, PublicKeyTemplate, RsaPrivateKeyTemplate, SecretKeyTemplate,
};
pub use mechanism::{
    Mechanism, MechanismFlags, MechanismInfo, MechanismType, RsaPkcsPssParams, MECH_RSA_PSS_SHA256,
    MECH_RSA_PSS_SHA384, MECH_RSA_PSS_SHA512,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biguint() {
        let expected = vec![0x80u8, 0x00u8];
        let num = BigUint::from(32768u64);
        assert_eq!(expected, num.to_bytes_be());
    }

    #[test]
    fn test_biguint_from_be() {
        let bytes = vec![0x80u8, 0x00u8];
        let expected = BigUint::from(32768u64);
        assert_eq!(expected, BigUint::from_bytes_be(&bytes));
    }
}
