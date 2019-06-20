use std::io::Read;
use std::{env, fs, io, sync};

use futures::future;
use futures::Stream;
use hyper::rt::Future;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use pkcs11::object::{BigUint, MechanismType, Object, RsaPrivateKeyTemplate};
use pkcs11::session::{Session, SessionFlags, UserType};
use pkcs11::{Module, ModuleBuilder};
use rustls::internal::msgs::enums::SignatureAlgorithm;
use rustls::internal::pemfile;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{Certificate, ResolvesServerCert};
use rustls::{SignatureScheme, TLSError};
use tokio_rustls::TlsAcceptor;

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

struct RsaSigner {
    key: sync::Arc<RsaKey>,
    mechanism: MechanismType,
    scheme: SignatureScheme,
}

impl RsaSigner {
    fn new(key: sync::Arc<RsaKey>, scheme: SignatureScheme) -> Box<Signer> {
        let mechanism = match scheme {
            SignatureScheme::RSA_PKCS1_SHA256 => MechanismType::Sha256RsaPkcs,
            SignatureScheme::RSA_PKCS1_SHA384 => MechanismType::Sha384RsaPkcs,
            SignatureScheme::RSA_PKCS1_SHA512 => MechanismType::Sha512RsaPkcs,
            SignatureScheme::RSA_PSS_SHA256 => MechanismType::Sha256RsaPkcsPss,
            SignatureScheme::RSA_PSS_SHA384 => MechanismType::Sha384RsaPkcsPss,
            SignatureScheme::RSA_PSS_SHA512 => MechanismType::Sha512RsaPkcsPss,
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
        println!("message {:?}", message);
        println!("mech type: {:?}", self.mechanism);
        self.key
            .session
            .sign(&self.key.key, self.mechanism, message)
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

    let module = ModuleBuilder::new()
        .path("/usr/local/lib/softhsm/libsofthsm2.so")
        .initialize()
        .unwrap();

    // Build TLS configuration.
    let tls_cfg = {
        // Load public certificate.
        let certs =
            load_certs("/home/miyagley/Code/rust/pkcs11-rs/pkcs11/examples/certs/sample.pem")?;
        // Load private key.
        let key = load_private_key_pkcs11(
            &module,
            "/home/miyagley/Code/rust/pkcs11-rs/pkcs11/examples/certs/sample.key.der",
        )?;
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
                // Ok(None)
                Err(_e)
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
fn load_private_key_pkcs11(module: &Module, filename: &str) -> io::Result<RsaKey> {
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    // Initialize pkcs11 module and login to session
    let session = module.session(595651617, SessionFlags::RW).unwrap();
    session.login(UserType::User, "1234").unwrap();

    // Import the key
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;

    let modulus = BigUint::parse_bytes(b"00a9561875fc534fdaabd67a76d94a085aae2fd44e1c1e7729df9c71bb81cdc99b282411d12b5813bf087cc782cc7b6e2544e5bf2c6583440ca1688f2a0f1c658ad9b40cfc54f29e224280d08b767ea152aab12c09a5ddcc465bbee1016bbde131c3181d6a15ef9e1620149c39a86fc80d66d0334fa2b26ff24625dac4534c23f9177bc146f89292c89cd1ff25cfa8cf68a2d808cd6c63995e7473ee1ecabf7b0ef6f00107261e2dc0a3dea9e17a31cca9585b013d4c0facd0dbe60a063139d8cb10294ff1854a6ef4a914c8b874731921df3ac588a87856ebed73e9fb69e3afda32663a5d5daf45cb9521c1966a0aa87e9d09349b75d40b9a52bb766b3cbc4d35", 16).unwrap();
    let public_exponent = BigUint::from(65537u64);
    let private_exponent = BigUint::parse_bytes(b"52ad649806b0aea6778bea9328984ae7eb7012da68443fae442d60224ac82d0d02564a14b472f6812925b34b9b87104a460f5e7dd0ba7c79263da4d8c633f928080f2edfeca1e0af9d84c34db4773350e76245bc182de8d4d96aa2f54ca392d5f709492348be8b9305eaca3424971f37dbe0ff8c7c455eff0d5ce22944fa41fd4b3744a368cafec45bcc7218f135f425b990e1208b2dacabdb6606bac231b4861c5addcc30ffc6da5b919d8cf30428dee4c5dda408651cb8b84c1eb1e21e4f981298739eee39536780a2dd632ad029cb335b8371e6fd1ae071b703912d517342728d7ee5ab173a0da562985061587647ed7082ee568838c356efba1188231529", 16).unwrap();
    let prime1 = BigUint::parse_bytes(b"00d0d064e850e8c44ff82ffe22278cc886ef41a6d37c25efee4b973ac117a3342fd5a90cb0ed21db85114dad73efab963ed9b23f0f1b5dcd92ca00c5ce3230e38f45c481f3889f66af78ea37b84ef37f58be9e3c704213eeb92600f40941662286af63c26120cf9d58873aca55263c51b8083258cd507fe0930b40fde5a8f4a33f", 16).unwrap();
    let prime2 = BigUint::parse_bytes(b"00cf99f809bdff59f507c4c24b96327b3e5566950a45e4793700e47dfafb6a4ed771463bb15ba0c7dae007043742dce829a543780858f9e64cdcd8752e887b663edc7c98ae86fa8b53ecbc30fa72d214be0fbd9e82631a9c8a8e4c3e7a1877ea42c6b5d8245a365bb7b816404ec5be4f1794a8e69960f9dd33fd0880eda14fd68b", 16).unwrap();
    let exponent1 = BigUint::parse_bytes(b"00b608b5af00b9aa49bca6b9f8b459ba8647150885dcf8858d4b406eebdddb5ca746afb46c988ca77dfd73a5fe27b581a910c69eca60a5098d29a43acc625cd444162214d76506f0d18fab3f1fe153cc7464d834fff7dac0858f67cd56343901684085caf23954446ae4988fc2632eba5ea066a39b78cdc1ccee469e10139610a9", 16).unwrap();
    let exponent2 = BigUint::parse_bytes(b"189cee95691b4f3507d8c2186814501c51cfb9b7e015787196ff8018339aa5025201bbae09690488e4aab04b44f81fe6601ba1ad8baf0528f3be0e169843d91976d6a6db7a5156177b27ccbec4c237875922681a99595c59e9090d1738b36ee8bfda6b67d3f241e9843fcf1c07c1ca6ac74b471bc42d9b964057b3c178b09885", 16).unwrap();
    let coefficient = BigUint::parse_bytes(b"00c02c9c54ffa84c4ddcad114e422ce05231bcb8e580ff46b7d0ae5da097fbc0d1eb4faeda3846456a52b9033bff56e2664e44294dde49f11054939588bc60e6e8c5d9729e915f85cb3cdb014286cf98769d5e12c54702ab6e4febb39f4b2ba327018817d507de3d2c4c67cc60c5524846d22d9cd889daad060b4ec2321c220310", 16).unwrap();

    let mut template = RsaPrivateKeyTemplate::new();
    template
        .label("tls-key".to_string())
        // .is_token_object(true)
        .modulus(modulus)
        .public_exponent(public_exponent)
        .private_exponent(private_exponent)
        .prime1(prime1)
        .prime2(prime2)
        .exponent1(exponent1)
        .exponent2(exponent2)
        .coefficient(coefficient)
        .can_sign(true);

    let key = session.create_object(&template).unwrap();
    Ok(RsaKey::new(session, key))
}
