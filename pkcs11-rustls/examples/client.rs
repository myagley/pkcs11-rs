use std::str::FromStr;
use std::{fs, io, sync};

use clap::{App, Arg};
use futures::{Future, Stream};
use hyper::{client, Uri};
use hyper_rustls::HttpsConnector;
use pkcs11::object::*;
use pkcs11::session::{SessionFlags, UserType};
use pkcs11::{Module, ModuleBuilder};
use pkcs11_rustls::{CertificateResolver, RsaKey};
use tokio_rustls::rustls::internal::pemfile;

fn app() -> App<'static, 'static> {
    App::new("server")
        .arg(Arg::with_name("addr").value_name("ADDR").required(true))
        .arg(
            Arg::with_name("cert")
                .short("c")
                .long("cert")
                .value_name("FILE")
                .help("cert file")
                .required(true),
        )
        .arg(
            Arg::with_name("key")
                .short("k")
                .long("key")
                .value_name("LABEL")
                .help("pkcs11 key label")
                .required(true),
        )
}

fn main() {
    env_logger::init();
    if let Err(e) = run_client() {
        eprintln!("FAILED: {}", e);
        std::process::exit(1);
    }
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

fn run_client() -> io::Result<()> {
    let matches = app().get_matches();
    let addr = matches.value_of("addr").unwrap();

    let uri = Uri::from_str(addr).map_err(|e| error(format!("{}", e)))?;
    let cert_file = matches.value_of("cert").unwrap();
    let key_label = matches.value_of("key").unwrap();

    let module = ModuleBuilder::new()
        .path("/usr/local/lib/softhsm/libsofthsm2.so")
        .initialize()
        .unwrap();

    // Build TLS configuration.
    let tls_cfg = {
        // Load public certificate.
        let certs = load_certs(cert_file)?;
        // Load private key.
        let key = load_private_key_pkcs11(&module, &key_label)?;
        // let key = load_private_key("/home/miyagley/Code/certs/private/iot-device-cert-device-primary.key.pem")?;
        // Do not use client certificate authentication.
        let mut cfg = rustls::ClientConfig::new();
        // Select a certificate to use.
        cfg.client_auth_cert_resolver = sync::Arc::new(CertificateResolver::new(certs, key));
        cfg.root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        // cfg.set_single_client_cert(certs, key);
        sync::Arc::new(cfg)
    };

    let mut http = client::HttpConnector::new(4);
    http.enforce_http(false);
    let https = HttpsConnector::from((http, tls_cfg));
    let client: client::Client<_, hyper::Body> = client::Client::builder().build(https);

    let fut = futures::future::ok(client)
        .and_then(|client| client.get(uri))
        .inspect(|res| {
            println!("Status:\n{}", res.status());
            println!("Headers:\n{:#?}", res.headers());
        })
        .and_then(|res| res.into_body().concat2())
        .inspect(|body| {
            println!("Body:\n{}", String::from_utf8_lossy(&body));
        });

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on_all(fut).map_err(|e| error(format!("{}", e)))?;
    Ok(())
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

// Load private key from hsm.
fn load_private_key_pkcs11<'m>(module: &'m Module, label: &str) -> io::Result<RsaKey> {
    // Initialize pkcs11 module and login to session
    let session = module
        .session(595651617, SessionFlags::RW)
        .map_err(|e| error(format!("get session failed with {}", e)))?;
    session
        .login(UserType::User, "1234")
        .map_err(|e| error(format!("login failed with {}", e)))?;

    let mut template = RsaPrivateKeyTemplate::new();
    template.label(label.to_string());
    let key = session
        .find_objects(&template)
        .map_err(|e| error(format!("find objects failed with {}", e)))?
        .into_iter()
        .nth(0)
        .ok_or(error("no key found".to_string()))?;
    Ok(RsaKey::new(key))
}
