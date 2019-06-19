use pkcs11_sys::*;

use crate::object::{Attribute, AttributeValue, ObjectClass, Template};

/// A value that identifies a certificate type.
///
/// Certificate types are defined with the objects and mechanisms that use them.
/// The certificate type is specified on an object through the
/// CKA_CERTIFICATE_TYPE attribute of the object.

/// Vendor defined values for this type may also be specified.
#[derive(Debug, PartialEq)]
pub enum CertificateType {
    X509,
    X509AttrCert,
    Wtls,
    Vendor,
}

impl From<CertificateType> for CK_CERTIFICATE_TYPE {
    fn from(cert_type: CertificateType) -> CK_CERTIFICATE_TYPE {
        match cert_type {
            CertificateType::Vendor => CKC_VENDOR_DEFINED as CK_CERTIFICATE_TYPE,
            CertificateType::Wtls => CKC_WTLS as CK_CERTIFICATE_TYPE,
            CertificateType::X509 => CKC_X_509 as CK_CERTIFICATE_TYPE,
            CertificateType::X509AttrCert => CKC_X_509_ATTR_CERT as CK_CERTIFICATE_TYPE,
        }
    }
}

pub struct X509CertificateTemplate {
    attributes: Vec<Attribute>,
}

impl X509CertificateTemplate {
    pub fn new() -> Self {
        let object_class = Attribute::new(
            CKA_CLASS.into(),
            AttributeValue::ObjectClass(ObjectClass::Certificate.into()),
        );
        let cert_type = Attribute::new(
            CKA_CERTIFICATE_TYPE.into(),
            AttributeValue::CertificateType(CertificateType::X509.into()),
        );
        let attributes = vec![object_class, cert_type];
        Self { attributes }
    }

    // Common attributes
    attr_bool!(is_token_object, CKA_TOKEN);
    attr_bool!(is_private, CKA_PRIVATE);
    attr_bool!(is_modifiable, CKA_MODIFIABLE);
    attr_string!(label, CKA_LABEL);
    attr_bool!(is_copyable, CKA_COPYABLE);
    attr_bool!(is_destroyable, CKA_DESTROYABLE);

    // Common certificate attributes
    attr_bool!(is_trusted, CKA_TRUSTED);
    attr_bytes!(check_value, CKA_CHECK_VALUE);
    // attr_date!(start_date, CKA_START_DATE);
    // attr_date!(end_date, CKA_END_DATE);
    attr_bytes!(public_key_info, CKA_PUBLIC_KEY_INFO);

    // x.509 public key certificate attributes
    attr_bytes!(subject, CKA_SUBJECT);
    attr_bytes!(id, CKA_ID);
    attr_bytes!(issuer, CKA_ISSUER);
    attr_bytes!(serial_number, CKA_SERIAL_NUMBER);
    attr_bytes!(value, CKA_VALUE);
    attr_string!(url, CKA_URL);
    attr_bytes!(hash_of_subject_public_key, CKA_HASH_OF_SUBJECT_PUBLIC_KEY);
    attr_bytes!(hash_of_issuer_public_key, CKA_HASH_OF_ISSUER_PUBLIC_KEY);
    attr_mech!(name_hash_algorithm, CKA_NAME_HASH_ALGORITHM);
}

impl Template for X509CertificateTemplate {
    fn attributes(&self) -> &[Attribute] {
        &self.attributes
    }
}
