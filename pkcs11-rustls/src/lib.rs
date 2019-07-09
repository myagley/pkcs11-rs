use std::ffi::c_void;
use std::sync;

use pkcs11::object::*;
use pkcs11::session::Session;
use pkcs11_sys::*;
use ring::digest::Algorithm;
use rustls::internal::msgs::enums::SignatureAlgorithm;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{Certificate, ResolvesServerCert};
use rustls::{SignatureScheme, TLSError};

pub struct Resolver(CertifiedKey);

impl Resolver {
    pub fn new(chain: Vec<Certificate>, priv_key: RsaKey) -> Self {
        let signing_key = Box::new(RsaSigningKey::new(priv_key));
        Resolver(CertifiedKey::new(chain, sync::Arc::new(signing_key)))
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(
        &self,
        _server_name: Option<webpki::DNSNameRef>,
        _sigschemes: &[SignatureScheme],
    ) -> Option<CertifiedKey> {
        Some(self.0.clone())
    }
}

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
    session: Session,
    key: Object,
}

impl RsaKey {
    pub fn new(session: Session, key: Object) -> Self {
        Self { session, key }
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
            .map(|scheme| RsaSigner::new(self.key.clone(), scheme))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

enum RsaMechanism {
    Pkcs1Sha256,
    Pkcs1Sha384,
    Pkcs1Sha512,
    PssSha256,
    PssSha384,
    PssSha512,
}

impl RsaMechanism {
    fn digest(&self) -> &'static Algorithm {
        match self {
            RsaMechanism::Pkcs1Sha256 => &ring::digest::SHA256,
            RsaMechanism::Pkcs1Sha384 => &ring::digest::SHA384,
            RsaMechanism::Pkcs1Sha512 => &ring::digest::SHA512,
            RsaMechanism::PssSha256 => &ring::digest::SHA256,
            RsaMechanism::PssSha384 => &ring::digest::SHA384,
            RsaMechanism::PssSha512 => &ring::digest::SHA512,
        }
    }
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
    fn new(key: sync::Arc<RsaKey>, scheme: SignatureScheme) -> Box<Signer> {
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
        let m_hash = ring::digest::digest(self.mechanism.digest(), message);

        self.key
            .session
            .sign(&self.key.key, &self.mechanism, m_hash.as_ref())
            .map_err(|e| TLSError::General(format!("signing failed with {}", e)))
    }

    fn get_scheme(&self) -> SignatureScheme {
        self.scheme
    }
}
