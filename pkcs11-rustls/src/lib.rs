use std::sync;

use pkcs11::object::*;
use pkcs11::session::Session;
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
    session: Session<'static>,
    key: Object,
}

impl RsaKey {
    pub fn new(session: Session<'static>, key: Object) -> Self {
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

struct RsaSigner {
    key: sync::Arc<RsaKey>,
    mechanism: &'static RsaPkcsPssParams,
    scheme: SignatureScheme,
}

impl RsaSigner {
    fn new(key: sync::Arc<RsaKey>, scheme: SignatureScheme) -> Box<Signer> {
        let mechanism = match scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => &MECH_RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384 => &MECH_RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512 => &MECH_RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA256 => &MECH_RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384 => &MECH_RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512 => &MECH_RSA_PSS_SHA512,
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
        let m_hash = ring::digest::digest(&ring::digest::SHA512, message);

        self.key
            .session
            .sign(&self.key.key, self.mechanism, m_hash.as_ref())
            .map_err(|e| TLSError::General(format!("signing failed with {}", e)))
    }

    fn get_scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

