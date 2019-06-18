use pkcs11::object::{KeyType, MechanismType, SecretKeyTemplate};
use pkcs11::session::{SessionFlags, UserType};
use pkcs11::{Error, ModuleBuilder};

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
    }
}

fn run() -> Result<(), Error> {
    // Initialize pkcs11 module
    let module = ModuleBuilder::new()
        .path("/usr/local/lib/softhsm/libsofthsm2.so")
        .initialize()?;
    let mut session = module.session(595651617, SessionFlags::empty())?;
    session.login(UserType::User, "1234")?;

    let mut template = SecretKeyTemplate::new();
    template
        .key_type(KeyType::Sha256Hmac)
        .label("sas-key".to_string())
        .value(
            base64::decode("vSnr9DjnpfTCTjtG1LpFv4Ie476NBtOAyjUPzg4Y+H8=").expect("Invalid base64"),
        );
    let key = session.create_object(&mut template)?;
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
