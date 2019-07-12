use std::collections::HashSet;
use std::convert::From;
use std::default::Default;
use std::ffi::c_void;
use std::mem;
use std::path::PathBuf;
use std::str;
use std::sync::{Arc, Mutex};

use failure::ResultExt;
use lazy_static::lazy_static;
use libloading as lib;
use pkcs11_sys::*;

#[macro_use]
mod error;
#[macro_use]
pub mod object;
pub mod session;

pub use crate::error::{Error, ErrorKind, Pkcs11Error};
use crate::object::{MechanismInfo, MechanismType};
use crate::session::{Session, SessionFlags};

lazy_static! {
    static ref INITIALIZED_CRYPTOKI: Mutex<HashSet<PathBuf>> = Mutex::new(HashSet::new());
}

#[derive(Clone)]
pub struct Module {
    inner: Arc<Inner>,
}

struct Inner {
    functions: CK_FUNCTION_LIST_PTR,
    _lib: lib::Library,
    version: CK_VERSION,
}

pub struct ModuleBuilder {
    module_path: PathBuf,
}

impl ModuleBuilder {
    pub fn new() -> Self {
        ModuleBuilder {
            module_path: "/usr/lib/opensc-pkcs11.so".into(),
        }
    }

    pub fn path<P: Into<PathBuf>>(&mut self, module_path: P) -> &mut Self {
        self.module_path = module_path.into();
        self
    }

    pub fn initialize(&self) -> Result<Module, Error> {
        let lib = lib::Library::new(&self.module_path).context(ErrorKind::LoadModule)?;
        let functions = unsafe {
            let mut list: CK_FUNCTION_LIST_PTR = mem::uninitialized();
            let func: lib::Symbol<unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV> = lib
                .get(b"C_GetFunctionList")
                .context(ErrorKind::LoadModule)?;
            func(&mut list);
            list
        };

        // Only initialize a particular library once
        let mut initialized = INITIALIZED_CRYPTOKI.lock().expect("poisoned");
        if !initialized.contains(&self.module_path) {
            unsafe {
                let arg = std::ptr::null_mut();
                let mut args = CK_C_INITIALIZE_ARGS {
                    CreateMutex: None,
                    DestroyMutex: None,
                    LockMutex: None,
                    UnlockMutex: None,
                    flags: CK_FLAGS::from(CKF_OS_LOCKING_OK),
                    pReserved: arg,
                };
                let initialize = (*functions)
                    .C_Initialize
                    .ok_or(ErrorKind::MissingFunction("C_Initialize"))?;
                try_ck!(
                    "C_Initialize",
                    initialize(&mut args as *mut _ as *mut c_void)
                );
            }
            initialized.insert(self.module_path.clone());
        }
        drop(initialized);

        let version = unsafe {
            CK_VERSION {
                major: (*functions).version.major,
                minor: (*functions).version.minor,
            }
        };

        let inner = Inner {
            functions,
            _lib: lib,
            version,
        };
        let module = Module {
            inner: Arc::new(inner),
        };
        Ok(module)
    }
}

impl Default for ModuleBuilder {
    fn default() -> Self {
        ModuleBuilder::new()
    }
}

impl Module {
    /// Cryptoki API version
    pub fn version(&self) -> Version {
        Version {
            major: self.inner.version.major,
            minor: self.inner.version.minor,
        }
    }

    /// Returns general information about the Cryptoki module
    pub fn info(&self) -> Result<Info, Error> {
        let info = unsafe {
            let mut info = Info {
                inner: mem::uninitialized(),
            };
            let get_info = (*self.inner.functions)
                .C_GetInfo
                .ok_or(ErrorKind::MissingFunction("C_GetInfo"))?;
            try_ck!("C_GetInfo", get_info(&mut info.inner));
            info
        };
        Ok(info)
    }

    /// Obtains information about a particular slot in the system.
    /// `slot_id` is the ID of the slot
    pub fn slot_info<S: Into<SlotId>>(&self, slot_id: S) -> Result<SlotInfo, Error> {
        let slot_info = unsafe {
            let mut slot_info = SlotInfo {
                inner: mem::uninitialized(),
            };
            let get_slot_info = (*self.inner.functions)
                .C_GetSlotInfo
                .ok_or(ErrorKind::MissingFunction("C_GetSlotInfo"))?;
            try_ck!(
                "C_GetSlotInfo",
                get_slot_info(slot_id.into().0, &mut slot_info.inner)
            );
            slot_info
        };
        Ok(slot_info)
    }

    /// Obtains information about a particular token in the system.
    /// slot_id is the ID of the token’s slot
    pub fn token_info<S: Into<SlotId>>(&self, slot_id: S) -> Result<TokenInfo, Error> {
        let token_info = unsafe {
            let mut token_info = TokenInfo {
                inner: mem::uninitialized(),
            };
            let get_token_info = (*self.inner.functions)
                .C_GetTokenInfo
                .ok_or(ErrorKind::MissingFunction("C_GetTokenInfo"))?;
            try_ck!(
                "C_GetTokenInfo",
                get_token_info(slot_id.into().0, &mut token_info.inner)
            );
            token_info
        };
        Ok(token_info)
    }

    /// obtains information about a particular mechanism possibly supported by
    /// a token.
    /// slotID is the ID of the token’s slot
    /// mechanism_type is the type of mechanism
    pub fn mechanism_info<S: Into<SlotId>>(
        &self,
        slot_id: S,
        mechanism_type: MechanismType,
    ) -> Result<MechanismInfo, Error> {
        let mechanism_info = unsafe {
            let mut mechanism_info = MechanismInfo {
                inner: mem::uninitialized(),
            };
            let get_mechanism_info = (*self.inner.functions)
                .C_GetMechanismInfo
                .ok_or(ErrorKind::MissingFunction("C_GetMechanismInfo"))?;
            try_ck!(
                "C_GetMechanismInfo",
                get_mechanism_info(
                    slot_id.into().0,
                    mechanism_type.into(),
                    &mut mechanism_info.inner
                )
            );
            mechanism_info
        };
        Ok(mechanism_info)
    }

    /// Used to obtain a list of mechanism types supported by a token.
    ///
    /// `slot_id` is the ID of the token’s slot
    pub fn mechanism_list<S: Into<SlotId>>(&self, slot_id: S) -> Result<Vec<MechanismType>, Error> {
        let types = unsafe {
            let slot_id = slot_id.into();
            let get_mechanism_list = (*self.inner.functions)
                .C_GetMechanismList
                .ok_or(ErrorKind::MissingFunction("C_GetMechanismList"))?;

            // Get the count of slots
            let mut count: CK_ULONG = mem::uninitialized();
            let arg = std::ptr::null_mut();
            try_ck!(
                "C_GetMechanismList",
                get_mechanism_list(slot_id.0, arg, (&mut count) as *mut CK_ULONG)
            );

            // Fill in the data
            let mut types = Vec::with_capacity(count as usize);
            try_ck!(
                "C_GetMechanismList",
                get_mechanism_list(slot_id.0, types.as_mut_ptr(), (&mut count) as *mut CK_ULONG)
            );
            types.set_len(count as usize);
            types
        };
        Ok(types
            .iter()
            .map(|type_| MechanismType::from(*type_))
            .collect())
    }

    /// Used to obtain a list of slots in the system
    pub fn slot_list(&self, option: SlotsOption) -> Result<Vec<SlotId>, Error> {
        let ids = unsafe {
            let token_present = if let SlotsOption::All = option {
                CK_FALSE as u8
            } else {
                CK_TRUE as u8
            };

            let get_slot_list = (*self.inner.functions)
                .C_GetSlotList
                .ok_or(ErrorKind::MissingFunction("C_GetSlotList"))?;

            // Get the count of slots
            let mut count: CK_ULONG = mem::uninitialized();
            let arg = std::ptr::null_mut();
            try_ck!(
                "C_GetSlotList",
                get_slot_list(token_present, arg, (&mut count) as *mut CK_ULONG)
            );

            // Fill in the data
            let mut slot_ids = Vec::with_capacity(count as usize);
            try_ck!(
                "C_GetSlotList",
                get_slot_list(
                    token_present,
                    slot_ids.as_mut_ptr(),
                    (&mut count) as *mut CK_ULONG
                )
            );
            slot_ids.set_len(count as usize);
            slot_ids
        };
        Ok(ids.iter().map(|id| SlotId(*id)).collect())
    }

    /// Opens a connection between an application and a particular token or
    /// sets up an application callback for token insertion
    pub fn session<S: Into<SlotId>>(
        &self,
        slot_id: S,
        mut flags: SessionFlags,
    ) -> Result<Session, Error> {
        let slot_id = slot_id.into();
        // (5.6) For legacy reasons, the CKF_SERIAL_SESSION bit MUST always be set
        flags.insert(SessionFlags::SERIAL);

        let session = unsafe {
            let p_application = std::ptr::null_mut();
            let open_session = (*self.inner.functions)
                .C_OpenSession
                .ok_or(ErrorKind::MissingFunction("C_OpenSession"))?;

            let mut handle = mem::uninitialized();
            try_ck!(
                "C_OpenSession",
                open_session(
                    slot_id.0,
                    flags.bits(),
                    p_application,
                    Option::None,
                    &mut handle,
                )
            );
            Session::new(self.clone(), slot_id, handle)
        };
        Ok(session)
    }
}

pub enum SlotsOption {
    All,
    TokenPresent,
}

#[derive(Debug, PartialEq)]
pub struct Version {
    major: u8,
    minor: u8,
}

impl Version {
    pub fn major(&self) -> u8 {
        self.major
    }

    pub fn minor(&self) -> u8 {
        self.minor
    }
}

pub struct Info {
    inner: CK_INFO,
}

impl Info {
    pub fn cryptoki_version(&self) -> Version {
        Version {
            major: self.inner.cryptokiVersion.major,
            minor: self.inner.cryptokiVersion.minor,
        }
    }

    pub fn manufacturer_id(&self) -> &str {
        unsafe { str::from_utf8_unchecked(&self.inner.manufacturerID) }
    }

    pub fn library_description(&self) -> &str {
        unsafe { str::from_utf8_unchecked(&self.inner.libraryDescription) }
    }

    pub fn library_version(&self) -> Version {
        Version {
            major: self.inner.libraryVersion.major,
            minor: self.inner.libraryVersion.minor,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct SlotId(CK_SLOT_ID);

impl From<u64> for SlotId {
    fn from(id: u64) -> SlotId {
        SlotId(id)
    }
}

pub struct SlotInfo {
    inner: CK_SLOT_INFO,
}

impl SlotInfo {
    pub fn slot_description(&self) -> &str {
        unsafe { str::from_utf8_unchecked(&self.inner.slotDescription) }
    }

    pub fn manufacturer_id(&self) -> &str {
        unsafe { str::from_utf8_unchecked(&self.inner.manufacturerID) }
    }

    pub fn hardware_version(&self) -> Version {
        Version {
            major: self.inner.hardwareVersion.major,
            minor: self.inner.hardwareVersion.minor,
        }
    }

    pub fn firmware_version(&self) -> Version {
        Version {
            major: self.inner.firmwareVersion.major,
            minor: self.inner.firmwareVersion.minor,
        }
    }
}

pub struct TokenInfo {
    inner: CK_TOKEN_INFO,
}

#[derive(Debug, PartialEq)]
pub struct Memory {
    total: usize,
    free: usize,
}

impl Memory {
    pub fn total(&self) -> usize {
        self.total
    }

    pub fn free(&self) -> usize {
        self.free
    }
}

impl TokenInfo {
    /// Application-defined label, assigned during token initialization.
    /// MUST be padded with the blank character (‘ ‘).  MUST NOT be
    /// null-terminated.
    pub fn label(&self) -> &str {
        unsafe { str::from_utf8_unchecked(&self.inner.label) }
    }

    /// ID of the device manufacturer.  MUST be padded with the blank
    /// character (‘ ‘).  MUST NOT be null-terminated.
    pub fn manufacturer_id(&self) -> &str {
        unsafe { str::from_utf8_unchecked(&self.inner.manufacturerID) }
    }

    /// Model of the device.  MUST be padded with the blank character
    /// (‘ ‘).  MUST NOT be null-terminated.
    pub fn model(&self) -> &str {
        unsafe { str::from_utf8_unchecked(&self.inner.model) }
    }

    /// Character-string serial number of the device.  MUST be padded with
    /// the blank character (‘ ‘).  MUST NOT be null-terminated.
    pub fn serial_number(&self) -> &str {
        unsafe { str::from_utf8_unchecked(&self.inner.serialNumber) }
    }

    /// Maximum number of sessions that can be opened with the token at one
    /// time by a single application
    pub fn max_session_count(&self) -> usize {
        self.inner.ulMaxSessionCount as usize
    }

    /// Number of sessions that this application currently has open with the
    /// token
    pub fn session_count(&self) -> usize {
        self.inner.ulSessionCount as usize
    }

    /// Maximum number of read/write sessions that can be opened with the token
    /// at one time by a single application
    pub fn max_rw_session_count(&self) -> usize {
        self.inner.ulMaxRwSessionCount as usize
    }

    /// Number of read/write sessions that this application currently has open
    /// with the token
    pub fn rw_session_count(&self) -> usize {
        self.inner.ulRwSessionCount as usize
    }

    /// Maximum length in bytes of the PIN
    pub fn max_pin_len(&self) -> usize {
        self.inner.ulMaxPinLen as usize
    }

    /// Minimum length in bytes of the PIN
    pub fn min_pin_len(&self) -> usize {
        self.inner.ulMinPinLen as usize
    }

    /// Memory stats in bytes in which public objects may be stored
    pub fn public_memory(&self) -> Memory {
        Memory {
            total: self.inner.ulTotalPublicMemory as usize,
            free: self.inner.ulFreePublicMemory as usize,
        }
    }

    /// Memory stats in bytes in which private objects may be stored
    pub fn private_memory(&self) -> Memory {
        Memory {
            total: self.inner.ulTotalPrivateMemory as usize,
            free: self.inner.ulFreePrivateMemory as usize,
        }
    }

    /// Version number of hardware
    pub fn hardware_version(&self) -> Version {
        Version {
            major: self.inner.hardwareVersion.major,
            minor: self.inner.hardwareVersion.minor,
        }
    }

    /// Version number of hardware
    pub fn firmware_version(&self) -> Version {
        Version {
            major: self.inner.firmwareVersion.major,
            minor: self.inner.firmwareVersion.minor,
        }
    }

    /// Current time as a character-string of length 16, represented in the
    /// format YYYYMMDDhhmmssxx (4 characters for the year;  2 characters each
    /// for the month, the day, the hour, the minute, and the second; and 2
    /// additional reserved ‘0’ characters).  The value of this field only
    /// makes sense for tokens equipped with a clock, as indicated in the token
    /// information flags
    pub fn utc_time(&self) -> &str {
        unsafe { str::from_utf8_unchecked(&self.inner.utcTime) }
    }

    /// True if the token has been initialized using C_InitToken or an
    /// equivalent mechanism outside the scope of this standard.
    pub fn is_initialized(&self) -> bool {
        (self.inner.flags & (CK_FLAGS::from(CKF_TOKEN_INITIALIZED))) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::object::MechanismFlags;

    #[test]
    fn test_version() {
        let module = ModuleBuilder::new()
            .path("/usr/local/lib/softhsm/libsofthsm2.so")
            .initialize()
            .unwrap();

        let expected = Version {
            major: 2,
            minor: 40,
        };
        assert_eq!(expected, module.version());
    }

    #[test]
    fn test_info() {
        let module = ModuleBuilder::new()
            .path("/usr/local/lib/softhsm/libsofthsm2.so")
            .initialize()
            .unwrap();
        let info = module.info().unwrap();
        let expected_library_version = Version { major: 2, minor: 5 };
        let expected_cryptoki_version = Version {
            major: 2,
            minor: 40,
        };
        assert_eq!(expected_cryptoki_version, info.cryptoki_version());
        assert_eq!("SoftHSM                         ", info.manufacturer_id());
        assert_eq!(expected_library_version, info.library_version());
        assert_eq!(
            "Implementation of PKCS11        ",
            info.library_description()
        );
    }

    #[test]
    fn test_slot_info() {
        let module = ModuleBuilder::new()
            .path("/usr/local/lib/softhsm/libsofthsm2.so")
            .initialize()
            .unwrap();
        let info = module.slot_info(1).unwrap();
        let expected_hardware_version = Version { major: 2, minor: 5 };
        let expected_firmware_version = Version { major: 2, minor: 5 };

        assert_eq!(expected_hardware_version, info.hardware_version());
        assert_eq!(expected_firmware_version, info.firmware_version());
        assert_eq!(
            "SoftHSM slot ID 0x1                                             ",
            info.slot_description()
        );
        assert_eq!("SoftHSM project                 ", info.manufacturer_id());
    }

    // ignore until we can initialize the token to test
    #[test]
    #[ignore]
    fn test_token_info() {
        let module = ModuleBuilder::new()
            .path("/usr/local/lib/softhsm/libsofthsm2.so")
            .initialize()
            .unwrap();
        let info = module.token_info(1).unwrap();
        let expected_hardware_version = Version { major: 2, minor: 5 };
        let expected_firmware_version = Version { major: 2, minor: 5 };
        let expected_public_memory = Memory {
            total: std::usize::MAX,
            free: std::usize::MAX,
        };
        let expected_private_memory = Memory {
            total: std::usize::MAX,
            free: std::usize::MAX,
        };

        assert!(info.is_initialized());
        assert_eq!(expected_hardware_version, info.hardware_version());
        assert_eq!(expected_firmware_version, info.firmware_version());
        assert_eq!("My token 1                      ", info.label());
        assert_eq!("SoftHSM project                 ", info.manufacturer_id());
        assert_eq!("SoftHSM v2      ", info.model());
        assert_eq!("7b7e19c466b73008", info.serial_number());
        // assert_eq!(std::usize::MAX, info.max_session_count());
        // assert_eq!(0, info.session_count());
        // assert_eq!(std::usize::MAX, info.max_rw_session_count());
        // assert_eq!(0, info.rw_session_count());
        assert_eq!(255, info.max_pin_len());
        assert_eq!(4, info.min_pin_len());
        assert_eq!(expected_public_memory, info.public_memory());
        assert_eq!(expected_private_memory, info.private_memory());
    }

    #[test]
    fn test_slots() {
        let module = ModuleBuilder::new()
            .path("/usr/local/lib/softhsm/libsofthsm2.so")
            .initialize()
            .unwrap();
        let slots = module.slot_list(SlotsOption::TokenPresent).unwrap();
        assert_eq!(2, slots.len());
    }

    #[test]
    fn test_mechanism_info() {
        let module = ModuleBuilder::new()
            .path("/usr/local/lib/softhsm/libsofthsm2.so")
            .initialize()
            .unwrap();
        let info = module.mechanism_info(1, MechanismType::Sha256Hmac).unwrap();
        assert_eq!(MechanismFlags::SIGN | MechanismFlags::VERIFY, info.flags());
        assert_eq!(32, info.min_key_size());
        assert_eq!(512, info.max_key_size());
    }

    #[test]
    fn test_mechanism_list() {
        let module = ModuleBuilder::new()
            .path("/usr/local/lib/softhsm/libsofthsm2.so")
            .initialize()
            .unwrap();
        let types = module.mechanism_list(1).unwrap();
        assert_eq!(72, types.len());
    }
}
