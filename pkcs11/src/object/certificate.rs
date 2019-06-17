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
    Wlts,
    Vendor,
}
