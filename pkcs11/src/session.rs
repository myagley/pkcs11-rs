use std::mem;
use std::ops::Drop;

use bitflags::bitflags;
use pkcs11_sys::*;

use crate::object::{MechanismType, Object, Template};
use crate::{Cryptoki, Error, ErrorKind, SlotId};

pub struct Session<'c> {
    pub(crate) slot_id: SlotId,
    pub(crate) cryptoki: &'c Cryptoki,
    pub(crate) handle: CK_SESSION_HANDLE,
}

impl<'c> Session<'c> {
    pub fn info(&self) -> Result<SessionInfo, Error> {
        let info = unsafe {
            let mut info = SessionInfo {
                inner: mem::uninitialized(),
            };
            let get_session = (*self.cryptoki.functions)
                .C_GetSessionInfo
                .ok_or(ErrorKind::MissingFunction("C_GetSessionInfo"))?;
            try_ck!(get_session(self.handle, &mut info.inner));
            info
        };
        Ok(info)
    }

    pub fn login(&mut self, user_type: UserType, pin: &str) -> Result<(), Error> {
        unsafe {
            let mut cpin = String::from(pin);
            let login = (*self.cryptoki.functions)
                .C_Login
                .ok_or(ErrorKind::MissingFunction("C_Login"))?;
            try_ck!(login(
                self.handle,
                user_type.into(),
                cpin.as_mut_str() as *mut str as *mut u8,
                cpin.len() as CK_ULONG
            ));
        }
        Ok(())
    }

    pub fn logout(&mut self) -> Result<(), Error> {
        unsafe {
            let logout = (*self.cryptoki.functions)
                .C_Logout
                .ok_or(ErrorKind::MissingFunction("C_Logout"))?;
            try_ck!(logout(self.handle));
        }
        Ok(())
    }

    pub fn create_object<T: Template>(&mut self, template: &mut T) -> Result<Object, Error> {
        let mut attributes = Vec::with_capacity(template.attributes().len());
        for attribute in template.attributes_mut() {
            let attr = CK_ATTRIBUTE {
                type_: attribute.key(),
                pValue: attribute.value().value(),
                ulValueLen: attribute.value().len(),
            };
            attributes.push(attr);
        }

        let object = unsafe {
            let create_object = (*self.cryptoki.functions)
                .C_CreateObject
                .ok_or(ErrorKind::MissingFunction("C_CreateObject"))?;
            let mut object = Object {
                handle: mem::uninitialized(),
            };

            try_ck!(create_object(
                self.handle,
                attributes.as_mut_ptr(),
                attributes.len() as CK_ULONG,
                &mut object.handle
            ));
            object
        };
        Ok(object)
    }

    pub fn destroy_object(&mut self, object: Object) -> Result<(), Error> {
        unsafe {
            let destroy_object = (*self.cryptoki.functions)
                .C_DestroyObject
                .ok_or(ErrorKind::MissingFunction("C_DestroyObject"))?;
            try_ck!(destroy_object(self.handle, object.handle));
        }
        Ok(())
    }

    pub fn sign(
        &mut self,
        key: &Object,
        mechanism: MechanismType,
        tbs: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Make a copy of the input. The API requires this to be *mut
        // but we don't want the caller to have to be mutable and we
        // still want to be safe-ish
        let mut tbs = Vec::from(tbs);
        let signature = unsafe {
            let sign_init = (*self.cryptoki.functions)
                .C_SignInit
                .ok_or(ErrorKind::MissingFunction("C_SignInit"))?;
            let sign = (*self.cryptoki.functions)
                .C_Sign
                .ok_or(ErrorKind::MissingFunction("C_Sign"))?;

            let null = std::ptr::null_mut();
            let mut mechanism = CK_MECHANISM {
                mechanism: mechanism.into(),
                pParameter: null,
                ulParameterLen: 0,
            };

            // Initialize the sign operation
            try_ck!(sign_init(self.handle, &mut mechanism, key.handle));

            // Get the size
            let mut size: CK_ULONG = mem::uninitialized();
            let null_ptr = std::ptr::null_mut();
            try_ck!(sign(
                self.handle,
                tbs.as_mut_ptr(),
                tbs.len() as CK_ULONG,
                null_ptr,
                &mut size
            ));

            // Get the signature
            let mut signature = Vec::with_capacity(size as usize);
            try_ck!(sign(
                self.handle,
                tbs.as_mut_ptr(),
                tbs.len() as CK_ULONG,
                signature.as_mut_ptr(),
                &mut size
            ));
            signature.set_len(size as usize);
            signature
        };
        Ok(signature)
    }
}

impl<'c> Drop for Session<'c> {
    fn drop(&mut self) {
        unsafe {
            if let Some(close) = (*self.cryptoki.functions).C_CloseSession {
                close(self.handle);
            }
        }
    }
}

bitflags! {
    pub struct SessionFlags: CK_FLAGS {
        const RW = CKF_RW_SESSION as CK_FLAGS;
        const SERIAL = CKF_SERIAL_SESSION as CK_FLAGS;
    }
}

pub struct SessionInfo {
    inner: CK_SESSION_INFO,
}

impl SessionInfo {
    pub fn slot_id(&self) -> SlotId {
        SlotId(self.inner.slotID)
    }

    pub fn state(&self) -> SessionState {
        SessionState::from(self.inner.state)
    }

    pub fn flags(&self) -> SessionFlags {
        SessionFlags::from_bits_truncate(self.inner.flags)
    }

    pub fn device_error(&self) -> CK_ULONG {
        self.inner.ulDeviceError
    }
}

#[derive(Debug, PartialEq)]
pub enum SessionState {
    RoPublic,
    RoUserFunctions,
    RwPublic,
    RwUserFunctions,
    RwSoFunctions,
    Unknown,
}

impl From<CK_STATE> for SessionState {
    fn from(state: CK_STATE) -> SessionState {
        match state as u32 {
            CKS_RO_PUBLIC_SESSION => SessionState::RoPublic,
            CKS_RO_USER_FUNCTIONS => SessionState::RoUserFunctions,
            CKS_RW_PUBLIC_SESSION => SessionState::RwPublic,
            CKS_RW_USER_FUNCTIONS => SessionState::RwUserFunctions,
            CKS_RW_SO_FUNCTIONS => SessionState::RwSoFunctions,
            _ => SessionState::Unknown,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum UserType {
    SecurityOfficer,
    User,
    ContextSpecific,
}

impl From<CK_USER_TYPE> for UserType {
    fn from(user_type: CK_USER_TYPE) -> UserType {
        match user_type as u32 {
            CKU_SO => UserType::SecurityOfficer,
            CKU_USER => UserType::User,
            CKU_CONTEXT_SPECIFIC => UserType::ContextSpecific,
            u => panic!("Unknown user type {}", u),
        }
    }
}

impl From<UserType> for CK_USER_TYPE {
    fn from(user_type: UserType) -> CK_USER_TYPE {
        match user_type {
            UserType::SecurityOfficer => CKU_SO as CK_USER_TYPE,
            UserType::User => CKU_USER as CK_USER_TYPE,
            UserType::ContextSpecific => CKU_CONTEXT_SPECIFIC as CK_USER_TYPE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{KeyType, SecretKeyTemplate};
    use crate::Builder;

    // #[test]
    // fn test_session_login() {
    //     let module = Builder::new()
    //         .module("/usr/local/lib/softhsm/libsofthsm2.so")
    //         .initialize()
    //         .unwrap();
    //     let mut session = module.session(595651617, SessionFlags::RW).unwrap();
    //     let info = session.info().unwrap();
    //
    //     assert_eq!(SessionState::RwPublic, info.state());
    //
    //     session.login(UserType::User, "1234").unwrap();
    //     let info = session.info().unwrap();
    //
    //     assert_eq!(SessionState::RwUserFunctions, info.state());
    //
    //     session.logout().unwrap();
    //     let info = session.info().unwrap();
    //
    //     assert_eq!(SessionState::RoPublic, info.state());
    // }

    #[test]
    fn test_create_object() {
        let module = Builder::new()
            .module("/usr/local/lib/softhsm/libsofthsm2.so")
            .initialize()
            .unwrap();
        let mut session = module.session(595651617, SessionFlags::RW).unwrap();
        session.login(UserType::User, "1234").unwrap();

        let mut template = SecretKeyTemplate::new();
        template
            .key_type(KeyType::Sha256Hmac)
            .can_sign(true)
            .can_verify(true)
            .value(base64::decode("vSnr9DjnpfTCTjtG1LpFv4Ie476NBtOAyjUPzg4Y+H8=").unwrap())
            // .is_token_object(true)
            .label("my secret key".to_string());
        let object = session.create_object(&mut template).unwrap();
    }
}
