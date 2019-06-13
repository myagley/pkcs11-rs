use std::mem;
use std::ops::Drop;
use std::path::PathBuf;
use std::str;

use failure::ResultExt;
use libloading as lib;
use pkcs11_sys::*;

mod error;
pub use crate::error::{Error, ErrorKind};

pub struct Cryptoki {
    functions: CK_FUNCTION_LIST_PTR,
    lib: lib::Library,
    version: CK_VERSION,
}

pub struct Builder {
    module_path: PathBuf,
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            module_path: "/usr/lib/opensc-pkcs11.so".into(),
        }
    }

    pub fn module<'a, P: Into<PathBuf>>(&'a mut self, module_path: P) -> &'a mut Self {
        self.module_path = module_path.into();
        self
    }

    pub fn initialize<'a>(&self) -> Result<Cryptoki, Error> {
        let lib = lib::Library::new("/usr/local/lib/softhsm/libsofthsm2.so")
            .context(ErrorKind::LoadModule)?;
        let functions = unsafe {
            let mut list: CK_FUNCTION_LIST_PTR = mem::uninitialized();
            let func: lib::Symbol<unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV> = lib
                .get(b"C_GetFunctionList")
                .context(ErrorKind::LoadModule)?;
            func(&mut list);
            list
        };

        unsafe {
            let arg = std::ptr::null_mut();
            (*functions).C_Initialize.ok_or(ErrorKind::LoadModule)?(arg);
        }

        let version = unsafe {
            CK_VERSION {
                major: (*functions).version.major,
                minor: (*functions).version.minor,
            }
        };

        let token = Cryptoki {
            functions,
            lib,
            version,
        };
        Ok(token)
    }
}

impl Cryptoki {
    pub fn version(&self) -> Version {
        Version {
            major: self.version.major,
            minor: self.version.minor,
        }
    }

    pub fn info(&self) -> Result<Info, Error> {
        let info = unsafe {
            let mut info = Info {
                inner: mem::uninitialized(),
            };
            (*self.functions).C_GetInfo.ok_or(ErrorKind::LoadModule)?(&mut info.inner);
            info
        };
        Ok(info)
    }
}

impl Drop for Cryptoki {
    fn drop(&mut self) {
        unsafe {
            if let Some(finalize) = (*self.functions).C_Finalize {
                let arg = std::ptr::null_mut();
                finalize(arg);
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn test_version() {
    //     let cryptoki = Builder::new()
    //         .module("/usr/local/lib/softhsm/libsofthsm2.so")
    //         .initialize()
    //         .unwrap();
    //
    //     let expected = Version {
    //         major: 2,
    //         minor: 40,
    //     };
    //     assert_eq!(expected, cryptoki.version());
    // }

    #[test]
    fn test_info() {
        let cryptoki = Builder::new()
            .module("/usr/local/lib/softhsm/libsofthsm2.so")
            .initialize()
            .unwrap();
        let info = cryptoki.info().unwrap();
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
}
