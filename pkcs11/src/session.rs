use std::ffi::c_void;
use std::fmt;
use std::mem;
use std::ops::Drop;

use bitflags::bitflags;
use pkcs11_sys::*;
use scopeguard::defer;

use crate::object::{Mechanism, Object, Template};
use crate::{Error, ErrorKind, Module, Pkcs11Error, SlotId};

pub struct Session<'m> {
    pub(crate) slot_id: SlotId,
    pub(crate) module: &'m Module,
    pub(crate) handle: CK_SESSION_HANDLE,
}

impl<'c> Session<'c> {
    pub fn info(&self) -> Result<SessionInfo, Error> {
        let info = unsafe {
            let mut info = SessionInfo {
                inner: mem::uninitialized(),
            };
            let get_session = (*self.module.functions)
                .C_GetSessionInfo
                .ok_or(ErrorKind::MissingFunction("C_GetSessionInfo"))?;
            try_ck!(
                "C_GetSessionInfo",
                get_session(self.handle, &mut info.inner)
            );
            info
        };
        Ok(info)
    }

    pub fn login(&mut self, user_type: UserType, pin: &str) -> Result<(), Error> {
        unsafe {
            let login = (*self.module.functions)
                .C_Login
                .ok_or(ErrorKind::MissingFunction("C_Login"))?;
            try_ck!(
                "C_Login",
                login(
                    self.handle,
                    user_type.into(),
                    pin.as_ptr() as *mut u8,
                    pin.len() as CK_ULONG
                )
            );
        }
        Ok(())
    }

    pub fn logout(&mut self) -> Result<(), Error> {
        unsafe {
            let logout = (*self.module.functions)
                .C_Logout
                .ok_or(ErrorKind::MissingFunction("C_Logout"))?;
            try_ck!("C_Logout", logout(self.handle));
        }
        Ok(())
    }

    pub fn create_object<T: Template>(&mut self, template: &T) -> Result<Object, Error> {
        let mut attributes = Vec::with_capacity(template.attributes().len());
        for attribute in template.attributes() {
            let attr = CK_ATTRIBUTE {
                type_: attribute.key(),
                pValue: attribute.value().value() as *mut c_void,
                ulValueLen: attribute.value().len(),
            };
            attributes.push(attr);
        }

        let object = unsafe {
            let create_object = (*self.module.functions)
                .C_CreateObject
                .ok_or(ErrorKind::MissingFunction("C_CreateObject"))?;
            let mut object = Object {
                handle: mem::uninitialized(),
            };

            try_ck!(
                "C_CreateObject",
                create_object(
                    self.handle,
                    attributes.as_mut_ptr(),
                    attributes.len() as CK_ULONG,
                    &mut object.handle
                )
            );
            object
        };
        Ok(object)
    }

    pub fn destroy_object(&mut self, object: Object) -> Result<(), Error> {
        unsafe {
            let destroy_object = (*self.module.functions)
                .C_DestroyObject
                .ok_or(ErrorKind::MissingFunction("C_DestroyObject"))?;
            try_ck!(
                "C_DestroyObject",
                destroy_object(self.handle, object.handle)
            );
        }
        Ok(())
    }

    pub fn find_objects<T: Template>(&mut self, template: &T) -> Result<Vec<Object>, Error> {
        let mut attributes = Vec::with_capacity(template.attributes().len());
        for attribute in template.attributes() {
            let attr = CK_ATTRIBUTE {
                type_: attribute.key(),
                pValue: attribute.value().value() as *mut c_void,
                ulValueLen: attribute.value().len(),
            };
            attributes.push(attr);
        }

        let objects = unsafe {
            let find_objects_init = (*self.module.functions)
                .C_FindObjectsInit
                .ok_or(ErrorKind::MissingFunction("C_FindObjectsInit"))?;
            let find_objects = (*self.module.functions)
                .C_FindObjects
                .ok_or(ErrorKind::MissingFunction("C_FindObjects"))?;
            let find_objects_final = (*self.module.functions)
                .C_FindObjectsFinal
                .ok_or(ErrorKind::MissingFunction("C_FindObjectsFinal"))?;

            try_ck!(
                "C_FindObjectsInit",
                find_objects_init(
                    self.handle,
                    attributes.as_mut_ptr(),
                    attributes.len() as CK_ULONG
                )
            );

            // scopeguard the call to find_objects_final so that it always
            // runs now that the find operation has been initialized
            defer! {{
                let rv = find_objects_final(self.handle);
                if rv == CKR_OK.into() {
                    log::trace!("C_FindObjectFinal succeeded");
                } else {
                    log::trace!("C_FindObjectFinal failed with {}", Pkcs11Error::from(rv.into()));
                }
            }}

            let mut object_count: CK_ULONG = mem::uninitialized();
            let cap = 8;
            let mut objects = Vec::with_capacity(cap);

            // this is a do-while loop in rust
            // the last expression is the end condition
            while {
                let mut chunk = Vec::with_capacity(cap);

                try_ck!(
                    "C_FindObjects",
                    find_objects(
                        self.handle,
                        chunk.as_mut_ptr(),
                        cap as CK_ULONG,
                        &mut object_count as *mut CK_ULONG
                    )
                );
                chunk.set_len(object_count as usize + chunk.len());
                chunk.reserve(object_count as usize);
                objects.append(&mut chunk);

                // exit loop when no more objects
                object_count != 0
            } {}
            objects.iter().map(|obj| Object { handle: *obj }).collect()
        };
        Ok(objects)
    }

    pub fn sign<M>(&mut self, key: &Object, mechanism: M, data: &[u8]) -> Result<Vec<u8>, Error>
    where
        M: Mechanism,
    {
        let signature = unsafe {
            let sign_init = (*self.module.functions)
                .C_SignInit
                .ok_or(ErrorKind::MissingFunction("C_SignInit"))?;
            let sign = (*self.module.functions)
                .C_Sign
                .ok_or(ErrorKind::MissingFunction("C_Sign"))?;

            let mut mechanism = CK_MECHANISM {
                mechanism: mechanism.r#type().into(),
                pParameter: mechanism.as_ptr() as *mut c_void,
                ulParameterLen: mechanism.len(),
            };

            // Initialize the sign operation
            try_ck!(
                "C_SignInit",
                sign_init(self.handle, &mut mechanism, key.handle)
            );

            // Get the size
            let mut size: CK_ULONG = mem::uninitialized();
            let null_ptr = std::ptr::null_mut();
            try_ck!(
                "C_Sign",
                sign(
                    self.handle,
                    data.as_ptr() as *mut u8,
                    data.len() as CK_ULONG,
                    null_ptr,
                    &mut size
                )
            );

            // Get the signature
            let mut signature = Vec::with_capacity(size as usize);
            try_ck!(
                "C_Sign",
                sign(
                    self.handle,
                    data.as_ptr() as *mut u8,
                    data.len() as CK_ULONG,
                    signature.as_mut_ptr(),
                    &mut size
                )
            );
            signature.set_len(size as usize);
            signature
        };
        Ok(signature)
    }

    pub fn verify<M>(
        &mut self,
        key: &Object,
        mechanism: M,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error>
    where
        M: Mechanism,
    {
        let verified = unsafe {
            let verify_init = (*self.module.functions)
                .C_VerifyInit
                .ok_or(ErrorKind::MissingFunction("C_VerifyInit"))?;
            let verify = (*self.module.functions)
                .C_Verify
                .ok_or(ErrorKind::MissingFunction("C_Verify"))?;

            let mut mechanism = CK_MECHANISM {
                mechanism: mechanism.r#type().into(),
                pParameter: mechanism.as_ptr() as *mut c_void,
                ulParameterLen: mechanism.len(),
            };

            // Initialize the sign operation
            try_ck!(
                "C_VerifyInit",
                verify_init(self.handle, &mut mechanism, key.handle)
            );

            // Verify
            let rv = verify(
                self.handle,
                data.as_ptr() as *mut u8,
                data.len() as CK_ULONG,
                signature.as_ptr() as *mut u8,
                signature.len() as CK_ULONG,
            );

            if rv == CKR_SIGNATURE_INVALID.into() {
                false
            } else {
                try_ck!("C_Verify", rv);
                true
            }
        };
        Ok(verified)
    }
}

impl<'c> fmt::Debug for Session<'c> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut d = f.debug_struct("Session");
        d.field("slot_id", &self.slot_id.0);
        d.field("handle", &self.handle);
        d.finish()
    }
}

impl<'c> Drop for Session<'c> {
    fn drop(&mut self) {
        unsafe {
            if let Some(close) = (*self.module.functions).C_CloseSession {
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
    use crate::ModuleBuilder;

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
        let module = ModuleBuilder::new()
            .path("/usr/local/lib/softhsm/libsofthsm2.so")
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
        let _object = session.create_object(&mut template).unwrap();
    }
}
