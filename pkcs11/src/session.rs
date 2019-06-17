use std::mem;
use std::ops::Drop;

use bitflags::bitflags;
use pkcs11_sys::*;

use crate::object::{Object, Template};
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
                .ok_or(ErrorKind::LoadModule)?;
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
                .ok_or(ErrorKind::LoadModule)?;
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
                .ok_or(ErrorKind::LoadModule)?;
            try_ck!(logout(self.handle));
        }
        Ok(())
    }

    pub fn create_object<'s, T: Template>(
        &'s mut self,
        template: &mut T,
    ) -> Result<Object<'c, 's>, Error> {
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
                .ok_or(ErrorKind::LoadModule)?;
            let mut object = Object {
                handle: mem::uninitialized(),
                session: self,
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
    use crate::object::*;
    use crate::Builder;

    #[test]
    fn test_session_info() {
        let module = Builder::new()
            .module("/usr/local/lib/softhsm/libsofthsm2.so")
            .initialize()
            .unwrap();
        let session = module.session(1723281416, SessionFlags::RW).unwrap();
        let info = session.info().unwrap();

        assert!(info.flags().contains(SessionFlags::RW));
        assert_eq!(SessionState::RwPublic, info.state());
    }

    #[test]
    fn test_session_login() {
        let module = Builder::new()
            .module("/usr/local/lib/softhsm/libsofthsm2.so")
            .initialize()
            .unwrap();
        let mut session = module.session(1723281416, SessionFlags::RW).unwrap();
        let info = session.info().unwrap();

        assert!(info.flags().contains(SessionFlags::RW));
        assert_eq!(SessionState::RwPublic, info.state());

        session.login(UserType::User, "1234").unwrap();
        let info = session.info().unwrap();

        assert!(info.flags().contains(SessionFlags::RW));
        assert_eq!(SessionState::RwUserFunctions, info.state());

        session.logout().unwrap();
        let info = session.info().unwrap();

        assert!(info.flags().contains(SessionFlags::RW));
        assert_eq!(SessionState::RwPublic, info.state());
    }

    // #[test]
    // fn test_create_object() {
    //     let module = Builder::new()
    //         .module("/usr/local/lib/softhsm/libsofthsm2.so")
    //         .initialize()
    //         .unwrap();
    //     let mut session = module.session(1723281416, SessionFlags::RW).unwrap();
    //     let info = session.info().unwrap();
    //
    //     assert!(info.flags().contains(SessionFlags::RW));
    //     assert_eq!(SessionState::RwPublic, info.state());
    //
    //     session.login(UserType::User, "1234").unwrap();
    //     let info = session.info().unwrap();
    //
    //     let mut template = SecretKeyTemplate::new();
    //     template.key_type(KeyType::Sha256Hmac)
    //         .can_sign(true)
    //         .can_verify(true)
    //         .can_wrap(true)
    //         .can_unwrap(true);
    //     let object = session.create_object(&mut template).unwrap();
    // }
}
