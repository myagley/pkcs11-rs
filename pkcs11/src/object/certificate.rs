use pkcs11_sys::*;

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
