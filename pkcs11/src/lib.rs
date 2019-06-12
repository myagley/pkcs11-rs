use std::mem;
use std::path::PathBuf;

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

        let cryptoki = Cryptoki {
            functions,
            lib,
            version,
        };
        Ok(cryptoki)
    }
}

impl Cryptoki {
    pub fn version(&self) -> Version {
        Version {
            major: self.version.major,
            minor: self.version.minor,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let expected = Version {
            major: 2,
            minor: 40,
        };
        let cryptoki = Builder::new()
            .module("/usr/local/lib/softhsm/libsofthsm2.so")
            .initialize()
            .unwrap();
        assert_eq!(expected, cryptoki.version());
    }
}
