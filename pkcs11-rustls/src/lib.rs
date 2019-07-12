use std::ffi::c_void;
use std::sync;

use pkcs11::object::*;
use pkcs11_sys::*;
use rustls::internal::msgs::enums::SignatureAlgorithm;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{Certificate, ResolvesClientCert, ResolvesServerCert};
use rustls::{SignatureScheme, TLSError};

pub struct CertificateResolver(CertifiedKey);

impl CertificateResolver {
    pub fn new(chain: Vec<Certificate>, priv_key: RsaKey) -> Self {
        let signing_key = Box::new(RsaSigningKey::new(priv_key));
        Self(CertifiedKey::new(chain, sync::Arc::new(signing_key)))
    }
}

impl ResolvesClientCert for CertificateResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<CertifiedKey> {
        // Return key if sig scheme is supported
        first_in_both(ALL_RSA_SCHEMES, sigschemes).map(|_| self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(
        &self,
        _server_name: Option<webpki::DNSNameRef>,
        _sigschemes: &[SignatureScheme],
    ) -> Option<CertifiedKey> {
        Some(self.0.clone())
    }
}

// TODO use the list of available mechanisms to drive this
// list instead of a static list
static ALL_RSA_SCHEMES: &'static [SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

fn first_in_both<T: Clone + PartialEq>(prefs: &[T], avail: &[T]) -> Option<T> {
    for p in prefs {
        if avail.contains(p) {
            return Some(p.clone());
        }
    }

    None
}

pub struct RsaKey {
    key: Object,
}

impl RsaKey {
    pub fn new(key: Object) -> Self {
        Self { key }
    }
}

struct RsaSigningKey {
    key: sync::Arc<RsaKey>,
}

impl RsaSigningKey {
    pub fn new(key: RsaKey) -> Self {
        Self {
            key: sync::Arc::new(key),
        }
    }
}

impl SigningKey for RsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<Signer>> {
        first_in_both(ALL_RSA_SCHEMES, offered)
            .map(|scheme| RsaSigner::from_key_and_scheme(self.key.clone(), scheme))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

#[derive(Debug)]
enum RsaMechanism {
    Pkcs1Sha256,
    Pkcs1Sha384,
    Pkcs1Sha512,
    PssSha256,
    PssSha384,
    PssSha512,
}

impl<'a> Mechanism for &'a RsaMechanism {
    fn r#type(&self) -> MechanismType {
        match self {
            RsaMechanism::Pkcs1Sha256 => MechanismType::Sha256RsaPkcs,
            RsaMechanism::Pkcs1Sha384 => MechanismType::Sha384RsaPkcs,
            RsaMechanism::Pkcs1Sha512 => MechanismType::Sha512RsaPkcs,
            RsaMechanism::PssSha256 => MECH_RSA_PSS_SHA256.r#type(),
            RsaMechanism::PssSha384 => MECH_RSA_PSS_SHA384.r#type(),
            RsaMechanism::PssSha512 => MECH_RSA_PSS_SHA512.r#type(),
        }
    }

    fn as_ptr(&self) -> *const c_void {
        match self {
            RsaMechanism::Pkcs1Sha256 => std::ptr::null(),
            RsaMechanism::Pkcs1Sha384 => std::ptr::null(),
            RsaMechanism::Pkcs1Sha512 => std::ptr::null(),
            RsaMechanism::PssSha256 => MECH_RSA_PSS_SHA256.as_ptr(),
            RsaMechanism::PssSha384 => MECH_RSA_PSS_SHA384.as_ptr(),
            RsaMechanism::PssSha512 => MECH_RSA_PSS_SHA512.as_ptr(),
        }
    }

    fn len(&self) -> CK_ULONG {
        match self {
            RsaMechanism::Pkcs1Sha256 => 0,
            RsaMechanism::Pkcs1Sha384 => 0,
            RsaMechanism::Pkcs1Sha512 => 0,
            RsaMechanism::PssSha256 => MECH_RSA_PSS_SHA256.len(),
            RsaMechanism::PssSha384 => MECH_RSA_PSS_SHA384.len(),
            RsaMechanism::PssSha512 => MECH_RSA_PSS_SHA512.len(),
        }
    }
}

struct RsaSigner {
    key: sync::Arc<RsaKey>,
    mechanism: RsaMechanism,
    scheme: SignatureScheme,
}

impl RsaSigner {
    fn from_key_and_scheme(key: sync::Arc<RsaKey>, scheme: SignatureScheme) -> Box<Signer> {
        let mechanism = match scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => RsaMechanism::Pkcs1Sha256,
            SignatureScheme::RSA_PKCS1_SHA384 => RsaMechanism::Pkcs1Sha384,
            SignatureScheme::RSA_PKCS1_SHA512 => RsaMechanism::Pkcs1Sha512,
            SignatureScheme::RSA_PSS_SHA256 => RsaMechanism::PssSha256,
            SignatureScheme::RSA_PSS_SHA384 => RsaMechanism::PssSha384,
            SignatureScheme::RSA_PSS_SHA512 => RsaMechanism::PssSha512,
            _ => unreachable!(),
        };

        Box::new(Self {
            key,
            mechanism,
            scheme,
        })
    }
}

impl Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TLSError> {
        let signed = match self.mechanism {
            RsaMechanism::Pkcs1Sha256 => self.key.key.sign(&self.mechanism, message),
            RsaMechanism::Pkcs1Sha384 => self.key.key.sign(&self.mechanism, message),
            RsaMechanism::Pkcs1Sha512 => self.key.key.sign(&self.mechanism, message),
            RsaMechanism::PssSha256 => self.key.key.sign(
                &self.mechanism,
                ring::digest::digest(&ring::digest::SHA256, message).as_ref(),
            ),
            RsaMechanism::PssSha384 => self.key.key.sign(
                &self.mechanism,
                ring::digest::digest(&ring::digest::SHA384, message).as_ref(),
            ),
            RsaMechanism::PssSha512 => self.key.key.sign(
                &self.mechanism,
                ring::digest::digest(&ring::digest::SHA512, message).as_ref(),
            ),
        };
        signed.map_err(|e| TLSError::General(format!("signing failed with {}", e)))
    }

    fn get_scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
