use std::mem;
use std::ops::Drop;

use bitflags::bitflags;
use pkcs11_sys::*;

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
            try_ck!((*self.cryptoki.functions)
                .C_GetSessionInfo
                .ok_or(ErrorKind::LoadModule)?(
                self.handle, &mut info.inner,
            ));
            info
        };
        Ok(info)
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

impl SessionState {
    pub(crate) fn from(state: CK_STATE) -> SessionState {
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

impl<'c> Drop for Session<'c> {
    fn drop(&mut self) {
        unsafe {
            if let Some(close) = (*self.cryptoki.functions).C_CloseSession {
                close(self.handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
