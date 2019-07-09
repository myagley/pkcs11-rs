use std::{env, fs, io, sync};

use futures::future;
use futures::Stream;
use hyper::rt::Future;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use lazy_static::lazy_static;
use pkcs11::object::*;
use pkcs11::session::{Session, SessionFlags, UserType};
use pkcs11::{Module, ModuleBuilder};
use rustls::internal::msgs::enums::SignatureAlgorithm;
use rustls::internal::pemfile;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{Certificate, ResolvesServerCert};
use rustls::{SignatureScheme, TLSError};
use tokio_rustls::TlsAcceptor;

lazy_static! {
    static ref MODULE: Module = ModuleBuilder::new()
        .path("/usr/local/lib/softhsm/libsofthsm2.so")
        .initialize()
        .unwrap();
}

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

pub fn first_in_both<T: Clone + PartialEq>(prefs: &[T], avail: &[T]) -> Option<T> {
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

fn main() {
    env_logger::init();
    // Serve an echo service over HTTPS, with proper error handling.
    if let Err(e) = run_server() {
        eprintln!("FAILED: {}", e);
        std::process::exit(1);
    }
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

fn run_server() -> io::Result<()> {
    // First parameter is port number (optional, defaults to 8080)
    let port = match env::args().nth(1) {
        Some(ref p) => p.to_owned(),
        None => "8080".to_owned(),
    };
    let addr = format!("127.0.0.1:{}", port)
        .parse()
        .map_err(|e| error(format!("{}", e)))?;

    // Build TLS configuration.
    let tls_cfg = {
        // Load public certificate.
        let certs =
            load_certs("/home/miyagley/Code/rust/pkcs11-rs/pkcs11/examples/certs/sample.pem")?;
        // Load private key.
        let key = load_private_key_pkcs11(&MODULE)?;
        // Do not use client certificate authentication.
        let mut cfg = rustls::ServerConfig::new(rustls::NoClientAuth::new());
        // Select a certificate to use.
        cfg.cert_resolver = sync::Arc::new(Resolver::new(certs, key));
        // cfg.set_single_cert(certs, key)
        //     .map_err(|e| error(format!("{}", e)))?;
        sync::Arc::new(cfg)
    };

    // Create a TCP listener via tokio.
    let tcp = tokio::net::TcpListener::bind(&addr)?;
    let tls_acceptor = TlsAcceptor::from(tls_cfg);
    // Prepare a long-running future stream to accept and serve cients.
    let tls = tcp
        .incoming()
        .and_then(move |s| tls_acceptor.accept(s))
        .then(|r| match r {
            Ok(x) => Ok::<_, io::Error>(Some(x)),
            Err(_e) => {
                println!("[!] Voluntary server halt due to client-connection error...");
                // Errors could be handled here, instead of server aborting.
                Ok(None)
                //Err(_e)
            }
        })
        .filter_map(|x| x);
    // Build a hyper server, which serves our custom echo service.
    let fut = Server::builder(tls).serve(|| service_fn(echo));

    // Run the future, keep going until an error occurs.
    println!("Starting to serve on https://{}.", addr);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on_all(fut).map_err(|e| error(format!("{}", e)))?;
    Ok(())
}

// Future result: either a hyper body or an error.
type ResponseFuture = Box<Future<Item = Response<Body>, Error = hyper::Error> + Send>;

// Custom echo service, handling two different routes and a
// catch-all 404 responder.
fn echo(req: Request<Body>) -> ResponseFuture {
    let mut response = Response::new(Body::empty());
    match (req.method(), req.uri().path()) {
        // Help route.
        (&Method::GET, "/") => {
            *response.body_mut() = Body::from("Try POST /echo\n");
        }
        // Echo service route.
        (&Method::POST, "/echo") => {
            *response.body_mut() = req.into_body();
        }
        // Catch-all 404.
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };
    Box::new(future::ok(response))
}

// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<rustls::Certificate>> {
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    pemfile::certs(&mut reader).map_err(|_| error("failed to load certificate".into()))
}

// Load private key from file.
fn load_private_key(filename: &str) -> io::Result<rustls::PrivateKey> {
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    let keys = pemfile::rsa_private_keys(&mut reader)
        .map_err(|_| error("failed to load private key".into()))?;
    if keys.len() != 1 {
        return Err(error("expected a single private key".into()));
    }
    Ok(keys[0].clone())
}

// Load private key from file.
fn load_private_key_pkcs11(module: &'static Module) -> io::Result<RsaKey> {
    // Initialize pkcs11 module and login to session
    let session = module
        .session(595651617, SessionFlags::RW)
        .map_err(|e| error(format!("get session failed with {}", e)))?;
    session
        .login(UserType::User, "1234")
        .map_err(|e| error(format!("login failed with {}", e)))?;

    let mut template = RsaPrivateKeyTemplate::new();
    template.label("tls2".to_string());
    let key = session
        .find_objects(&template)
        .map_err(|e| error(format!("find objects failed with {}", e)))?
        .into_iter()
        .nth(0)
        .ok_or(error("no key found".to_string()))?;
    Ok(RsaKey::new(session, key))
}
