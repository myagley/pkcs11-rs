use std::ffi::c_void;
use std::mem;

use pkcs11_sys::*;

/// A token-specific identifier for an object.
pub struct Object {
    pub(crate) handle: CK_OBJECT_HANDLE,
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
            ObjectClass::Certificate => CKO_CERTIFICATE as CK_OBJECT_CLASS,
            ObjectClass::Data => CKO_DATA as CK_OBJECT_CLASS,
            ObjectClass::DomainParameters => CKO_DOMAIN_PARAMETERS as CK_OBJECT_CLASS,
            ObjectClass::HwFeature => CKO_HW_FEATURE as CK_OBJECT_CLASS,
            ObjectClass::OtpKey => CKO_OTP_KEY as CK_OBJECT_CLASS,
            ObjectClass::PrivateKey => CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
            ObjectClass::PublicKey => CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
            ObjectClass::SecretKey => CKO_SECRET_KEY as CK_OBJECT_CLASS,
            ObjectClass::Vendor => CKO_VENDOR_DEFINED as CK_OBJECT_CLASS,
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

    pub(crate) fn value(&mut self) -> &mut AttributeValue {
        &mut self.value
    }
}

pub(crate) enum AttributeValue {
    ObjectClass(CK_OBJECT_CLASS),
    CertificateType(CK_CERTIFICATE_TYPE),
    HwFeatureType(CK_HW_FEATURE_TYPE),
    KeyType(CK_KEY_TYPE),
    Bool(CK_BBOOL),
    Bytes(Vec<u8>),
    Num(CK_ULONG),
    String(String),
    Date(CK_DATE),
}

impl AttributeValue {
    pub(crate) fn value(&mut self) -> *mut c_void {
        match self {
            AttributeValue::ObjectClass(ref mut obj) => obj as *mut _ as *mut c_void,
            AttributeValue::CertificateType(ref mut cert) => cert as *mut _ as *mut c_void,
            AttributeValue::HwFeatureType(ref mut feat) => feat as *mut _ as *mut c_void,
            AttributeValue::KeyType(ref mut key) => key as *mut _ as *mut c_void,
            AttributeValue::Bool(ref mut b) => b as *mut _ as *mut c_void,
            AttributeValue::Bytes(ref mut b) => b.as_mut_ptr() as *mut c_void,
            AttributeValue::Num(ref mut n) => n as *mut _ as *mut c_void,
            AttributeValue::String(ref mut s) => unsafe {
                s.as_bytes_mut() as *mut _ as *mut c_void
            },
            AttributeValue::Date(ref mut d) => d as *mut _ as *mut c_void,
        }
    }

    pub(crate) fn len(&self) -> CK_ULONG {
        match self {
            AttributeValue::ObjectClass(_) => mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
            AttributeValue::CertificateType(_) => mem::size_of::<CK_CERTIFICATE_TYPE>() as CK_ULONG,
            AttributeValue::HwFeatureType(_) => mem::size_of::<CK_HW_FEATURE_TYPE>() as CK_ULONG,
            AttributeValue::KeyType(_) => mem::size_of::<CK_KEY_TYPE>() as CK_ULONG,
            AttributeValue::Bool(_) => mem::size_of::<CK_BBOOL>() as CK_ULONG,
            AttributeValue::Bytes(b) => b.len() as CK_ULONG,
            AttributeValue::Num(_) => mem::size_of::<CK_ULONG>() as CK_ULONG,
            AttributeValue::String(s) => s.as_bytes().len() as CK_ULONG,
            AttributeValue::Date(_) => mem::size_of::<CK_DATE>() as CK_ULONG,
        }
    }
}

pub trait Template {
    fn attributes(&self) -> &[Attribute];
    fn attributes_mut(&mut self) -> &mut [Attribute];
}

macro_rules! r#attr_bool {
    ($op:ident,$attr:ident) => {
        pub fn $op<'a>(&'a mut self, $op: bool) -> &'a mut Self {
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

macro_rules! r#attr_bytes {
    ($op:ident,$attr:ident) => {
        pub fn $op<'a>(&'a mut self, $op: Vec<u8>) -> &'a mut Self {
            let attribute = $crate::object::Attribute::new(pkcs11_sys::$attr.into(), $crate::object::AttributeValue::Bytes($op));
            self.attributes.push(attribute);
            self
        }
    }
}

macro_rules! r#attr_string {
    ($op:ident,$attr:ident) => {
        pub fn $op<'a>(&'a mut self, $op: String) -> &'a mut Self {
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

pub use certificate::CertificateType;
pub use hardware::HwFeatureType;
pub use key::{KeyType, PrivateKeyTemplate, PublicKeyTemplate, SecretKeyTemplate};
pub use mechanism::{MechanismFlags, MechanismInfo, MechanismType};
