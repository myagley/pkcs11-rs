use pkcs11::object::{KeyType, MechanismType, SecretKeyTemplate};
use pkcs11::session::{SessionFlags, UserType};
use pkcs11::{Error, ModuleBuilder};

fn main() {
    env_logger::init();
    if let Err(e) = run() {
        eprintln!("{}", e);
    }
}

fn run() -> Result<(), Error> {
    let key_bytes =
        base64::decode("vSnr9DjnpfTCTjtG1LpFv4Ie476NBtOAyjUPzg4Y+H8=").expect("Invalid base64");

    // Initialize pkcs11 module and login to session
    let module = ModuleBuilder::new()
        .path("/usr/local/lib/softhsm/libsofthsm2.so")
        .initialize()?;
    let mut session = module.session(595651617, SessionFlags::RW)?;
    session.login(UserType::User, "1234")?;

    // Import the key
    let mut template = SecretKeyTemplate::new();
    template
        .key_type(KeyType::Sha256Hmac)
        .label("sas-key".to_string())
        // .is_token_object(true)
        .value(key_bytes);
    let key = session.create_object(&template)?;

    // Sign and verify
    let signature = session.sign(&key, MechanismType::Sha256Hmac, "hello".as_bytes())?;
    let verified = session.verify(
        &key,
        MechanismType::Sha256Hmac,
        "hello".as_bytes(),
        &signature,
    )?;
    println!("signature: {}", base64::encode(&signature));
    println!("verified:  {}", verified);
    Ok(())
}
