use pkcs11::object::{KeyType, SecretKeyTemplate};
use pkcs11::session::{SessionFlags, UserType};
use pkcs11::{Error, ModuleBuilder};

fn main() {
    env_logger::init();
    if let Err(e) = run() {
        eprintln!("{}", e);
    }
}

fn run() -> Result<(), Error> {
    // Initialize pkcs11 module and login to session
    let module = ModuleBuilder::new()
        .path("/usr/local/lib/softhsm/libsofthsm2.so")
        .initialize()?;
    let session = module.session(595_651_617, SessionFlags::RW)?;
    session.login(UserType::User, "1234")?;

    // Import the key
    let mut template = SecretKeyTemplate::new();
    template
        .label("my secret key".to_string())
        .key_type(KeyType::Sha256Hmac);
    let objects = session.find_objects(&template)?;

    for object in objects {
        println!("object: {:?}", object);
    }
    Ok(())
}
