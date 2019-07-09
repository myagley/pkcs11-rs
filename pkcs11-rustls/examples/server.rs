use std::net::ToSocketAddrs;
use std::{fs, io, sync};

use clap::{App, Arg};
use futures::future;
use futures::Stream;
use hyper::rt::Future;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use pkcs11::object::*;
use pkcs11::session::{SessionFlags, UserType};
use pkcs11::{Module, ModuleBuilder};
use pkcs11_rustls::{Resolver, RsaKey};
use tokio_rustls::rustls::internal::pemfile;
use tokio_rustls::TlsAcceptor;

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
    let matches = app().get_matches();
    let addr = matches
        .value_of("addr")
        .unwrap()
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

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

// // Load private key from file.
// fn load_private_key(filename: &str) -> io::Result<rustls::PrivateKey> {
//     // Open keyfile.
//     let keyfile = fs::File::open(filename)
//         .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
//     let mut reader = io::BufReader::new(keyfile);
//
//     // Load and return a single private key.
//     let keys = pemfile::rsa_private_keys(&mut reader)
//         .map_err(|_| error("failed to load private key".into()))?;
//     if keys.len() != 1 {
//         return Err(error("expected a single private key".into()));
//     }
//     Ok(keys[0].clone())
// }

// Load private key from file.
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
