use pkcs11::object::{KeyType, MechanismType, SecretKeyTemplate};
use pkcs11::session::{SessionFlags, UserType};
use pkcs11::{Builder, Error};

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
    }
}

fn run() -> Result<(), Error> {
    let module = Builder::new()
        .module("/usr/local/lib/softhsm/libsofthsm2.so")
        .initialize()?;
    let mut session = module.session(595651617, SessionFlags::empty())?;
    session.login(UserType::User, "1234")?;

    let mut template = SecretKeyTemplate::new();
    template
        .key_type(KeyType::Sha256Hmac)
        .can_sign(true)
        .can_verify(true)
        .value(
            base64::decode("vSnr9DjnpfTCTjtG1LpFv4Ie476NBtOAyjUPzg4Y+H8=").expect("Invalid base64"),
        )
        // .is_token_object(true)
        .label("my secret key".to_string());
    let object = session.create_object(&mut template)?;
    let signature = session.sign(&object, MechanismType::Sha256Hmac, "hello".as_bytes())?;
    println!("signature: \"{}\"", base64::encode(&signature));

    Ok(())
}
