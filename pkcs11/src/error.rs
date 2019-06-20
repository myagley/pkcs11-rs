use std::fmt::{self, Display};

use failure::{Backtrace, Context, Fail};
use pkcs11_sys::*;

#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "Failed to load pkcs11 module.")]
    LoadModule,
    #[fail(display = "Failed to init pkcs11 module.")]
    InitModule,
    #[fail(display = "Missing function \"{}\"", _0)]
    MissingFunction(&'static str),
    #[fail(display = "{} failed with {}", _0, _1)]
    Function(&'static str, Pkcs11Error),
}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        *self.inner.get_context()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner: inner }
    }
}

/// Error values for Cryptoki functions
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Pkcs11Error {
    Cancel,
    /// The computer that the Cryptoki library is running on has insufficient
    /// memory to perform the requested function.
    HostMemory,

    /// The specified slot ID is not valid.
    SlotIdInvalid,

    /// Some horrible, unrecoverable error has occurred.
    /// In the worst case, it is possible that the function only partially
    /// succeeded, and that the computer and/or token is in an inconsistent
    /// state.
    GeneralError,

    /// The requested function could not be performed, but detailed
    /// information about why not is not available in this error return.
    ///
    /// If the function uses a session, it's possible the session info
    /// will provide more information.
    FunctionFailed,

    /// This is a rather generic error code which indicates that the arguments
    /// supplied to the Cryptoki function were in some way not appropriate.
    ArgumentsBad,

    /// This value can only be returned by C_GetSlotEvent. It is returned
    /// when C_GetSlotEvent is called in non-blocking mode and there are no
    /// new slot events to return.
    NoEvent,
    NeedToCreateThreads,
    CantLock,
    AttributeReadOnly,
    AttributeSensitive,
    AttributeTypeInvalid,
    AttributeValueInvalid,
    ActionProhibited,

    DataInvalid,
    DataLenRange,
    DeviceError,
    DeviceMemory,
    DeviceRemoved,
    EncryptedDataInvalid,
    EncryptedDataLenRange,
    FunctionCanceled,
    FunctionNotParallel,
    FunctionNotSupported,
    KeyHandleInvalid,
    KeySizeRange,
    KeyTypeInconsistent,
    KeyNotNeeded,
    KeyChanged,
    KeyNeeded,
    KeyIndigestible,
    KeyFunctionNotPermitted,
    KeyNotWrappable,
    KeyUnextractable,
    MechanismInvalid,
    MechanismParamInvalid,
    ObjectHandleInvalid,
    OperationActive,
    OperationNotInitialized,
    PinIncorrect,
    PinInvalid,
    PinLenRange,
    PinExpired,
    PinLocked,

    SessionClosed,
    SessionCount,
    SessionHandleInvalid,
    SessionParallelNotSupported,
    SessionReadOnly,
    SessionExists,

    SessionReadOnlyExists,
    SessionReadWriteSoExists,

    SignatureInvalid,
    SignatureLenRange,
    TemplateIncomplete,
    TemplateInconsistent,
    TokenNotPresent,
    TokenNotRecognized,
    TokenWriteProtected,

    UnwrappingKeyHandleInvalid,
    UnwrappingKeySizeRange,
    UnwrappingKeyTypeInconsistent,

    UserAlreadyLoggedIn,
    UserNotLoggedIn,
    UserPinNotInitialized,
    UserTypeInvalid,

    UserAnotherAlreadyLoggedIn,
    UserTooManyTypes,

    WrappedKeyInvalid,
    WrappedKeyLenRange,
    WrappingKeyHandleInvalid,
    WrappingKeySizeRange,
    WrappingKeyTypeInconsistent,
    RandomSeedNotSupported,

    RandomNoRng,
    DomainParamsInvalid,

    CurveNotSupported,
    BufferTooSmall,
    SavedStateInvalid,
    InformationSensitive,
    StateUnsaveable,

    CryptokiNotInitialized,
    CryptokiAlreadyInitialized,
    MutexBad,
    MutexNotLocked,

    NewPinMode,
    NextOtp,

    ExceededMaxIterations,
    FipsSelfTestFailed,
    LibraryLoadFailed,
    PinTooWeak,
    PublicKeyInvalid,

    FunctionRejected,
    VendorDefined,

    Unknown,
}

impl Pkcs11Error {
    pub(crate) fn from(rv: CK_RV) -> Pkcs11Error {
        match rv as u32 {
            CKR_CANCEL => Pkcs11Error::Cancel,
            CKR_HOST_MEMORY => Pkcs11Error::HostMemory,
            CKR_SLOT_ID_INVALID => Pkcs11Error::SlotIdInvalid,
            CKR_GENERAL_ERROR => Pkcs11Error::GeneralError,
            CKR_FUNCTION_FAILED => Pkcs11Error::FunctionFailed,
            CKR_ARGUMENTS_BAD => Pkcs11Error::ArgumentsBad,
            CKR_NO_EVENT => Pkcs11Error::NoEvent,
            CKR_NEED_TO_CREATE_THREADS => Pkcs11Error::NeedToCreateThreads,
            CKR_CANT_LOCK => Pkcs11Error::CantLock,
            CKR_ATTRIBUTE_READ_ONLY => Pkcs11Error::AttributeReadOnly,
            CKR_ATTRIBUTE_SENSITIVE => Pkcs11Error::AttributeSensitive,
            CKR_ATTRIBUTE_TYPE_INVALID => Pkcs11Error::AttributeTypeInvalid,
            CKR_ATTRIBUTE_VALUE_INVALID => Pkcs11Error::AttributeValueInvalid,
            CKR_ACTION_PROHIBITED => Pkcs11Error::ActionProhibited,
            CKR_DATA_INVALID => Pkcs11Error::DataInvalid,
            CKR_DATA_LEN_RANGE => Pkcs11Error::DataLenRange,
            CKR_DEVICE_ERROR => Pkcs11Error::DeviceError,
            CKR_DEVICE_MEMORY => Pkcs11Error::DeviceMemory,
            CKR_DEVICE_REMOVED => Pkcs11Error::DeviceRemoved,
            CKR_ENCRYPTED_DATA_INVALID => Pkcs11Error::EncryptedDataInvalid,
            CKR_ENCRYPTED_DATA_LEN_RANGE => Pkcs11Error::EncryptedDataLenRange,
            CKR_FUNCTION_CANCELED => Pkcs11Error::FunctionCanceled,
            CKR_FUNCTION_NOT_PARALLEL => Pkcs11Error::FunctionNotParallel,
            CKR_FUNCTION_NOT_SUPPORTED => Pkcs11Error::FunctionNotSupported,
            CKR_KEY_HANDLE_INVALID => Pkcs11Error::KeyHandleInvalid,
            CKR_KEY_SIZE_RANGE => Pkcs11Error::KeySizeRange,
            CKR_KEY_TYPE_INCONSISTENT => Pkcs11Error::KeyTypeInconsistent,
            CKR_KEY_NOT_NEEDED => Pkcs11Error::KeyNotNeeded,
            CKR_KEY_CHANGED => Pkcs11Error::KeyChanged,
            CKR_KEY_NEEDED => Pkcs11Error::KeyNeeded,
            CKR_KEY_INDIGESTIBLE => Pkcs11Error::KeyIndigestible,
            CKR_KEY_FUNCTION_NOT_PERMITTED => Pkcs11Error::KeyFunctionNotPermitted,
            CKR_KEY_NOT_WRAPPABLE => Pkcs11Error::KeyNotWrappable,
            CKR_KEY_UNEXTRACTABLE => Pkcs11Error::KeyUnextractable,
            CKR_MECHANISM_INVALID => Pkcs11Error::MechanismInvalid,
            CKR_MECHANISM_PARAM_INVALID => Pkcs11Error::MechanismParamInvalid,
            CKR_OBJECT_HANDLE_INVALID => Pkcs11Error::ObjectHandleInvalid,
            CKR_OPERATION_ACTIVE => Pkcs11Error::OperationActive,
            CKR_OPERATION_NOT_INITIALIZED => Pkcs11Error::OperationNotInitialized,
            CKR_PIN_INCORRECT => Pkcs11Error::PinIncorrect,
            CKR_PIN_INVALID => Pkcs11Error::PinInvalid,
            CKR_PIN_LEN_RANGE => Pkcs11Error::PinLenRange,
            CKR_PIN_EXPIRED => Pkcs11Error::PinExpired,
            CKR_PIN_LOCKED => Pkcs11Error::PinLocked,
            CKR_SESSION_CLOSED => Pkcs11Error::SessionClosed,
            CKR_SESSION_COUNT => Pkcs11Error::SessionCount,
            CKR_SESSION_HANDLE_INVALID => Pkcs11Error::SessionHandleInvalid,
            CKR_SESSION_PARALLEL_NOT_SUPPORTED => Pkcs11Error::SessionParallelNotSupported,
            CKR_SESSION_READ_ONLY => Pkcs11Error::SessionReadOnly,
            CKR_SESSION_EXISTS => Pkcs11Error::SessionExists,
            CKR_SESSION_READ_ONLY_EXISTS => Pkcs11Error::SessionReadOnlyExists,
            CKR_SESSION_READ_WRITE_SO_EXISTS => Pkcs11Error::SessionReadWriteSoExists,
            CKR_SIGNATURE_INVALID => Pkcs11Error::SignatureInvalid,
            CKR_SIGNATURE_LEN_RANGE => Pkcs11Error::SignatureLenRange,
            CKR_TEMPLATE_INCOMPLETE => Pkcs11Error::TemplateIncomplete,
            CKR_TEMPLATE_INCONSISTENT => Pkcs11Error::TemplateInconsistent,
            CKR_TOKEN_NOT_PRESENT => Pkcs11Error::TokenNotPresent,
            CKR_TOKEN_NOT_RECOGNIZED => Pkcs11Error::TokenNotRecognized,
            CKR_TOKEN_WRITE_PROTECTED => Pkcs11Error::TokenWriteProtected,
            CKR_UNWRAPPING_KEY_HANDLE_INVALID => Pkcs11Error::UnwrappingKeyHandleInvalid,
            CKR_UNWRAPPING_KEY_SIZE_RANGE => Pkcs11Error::UnwrappingKeySizeRange,
            CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT => Pkcs11Error::UnwrappingKeyTypeInconsistent,
            CKR_USER_ALREADY_LOGGED_IN => Pkcs11Error::UserAlreadyLoggedIn,
            CKR_USER_NOT_LOGGED_IN => Pkcs11Error::UserNotLoggedIn,
            CKR_USER_PIN_NOT_INITIALIZED => Pkcs11Error::UserPinNotInitialized,
            CKR_USER_TYPE_INVALID => Pkcs11Error::UserTypeInvalid,
            CKR_USER_ANOTHER_ALREADY_LOGGED_IN => Pkcs11Error::UserAnotherAlreadyLoggedIn,
            CKR_USER_TOO_MANY_TYPES => Pkcs11Error::UserTooManyTypes,
            CKR_WRAPPED_KEY_INVALID => Pkcs11Error::WrappedKeyInvalid,
            CKR_WRAPPED_KEY_LEN_RANGE => Pkcs11Error::WrappedKeyLenRange,
            CKR_WRAPPING_KEY_HANDLE_INVALID => Pkcs11Error::WrappingKeyHandleInvalid,
            CKR_WRAPPING_KEY_SIZE_RANGE => Pkcs11Error::WrappingKeySizeRange,
            CKR_WRAPPING_KEY_TYPE_INCONSISTENT => Pkcs11Error::WrappingKeyTypeInconsistent,
            CKR_RANDOM_SEED_NOT_SUPPORTED => Pkcs11Error::RandomSeedNotSupported,
            CKR_RANDOM_NO_RNG => Pkcs11Error::RandomNoRng,
            CKR_DOMAIN_PARAMS_INVALID => Pkcs11Error::DomainParamsInvalid,
            CKR_CURVE_NOT_SUPPORTED => Pkcs11Error::CurveNotSupported,
            CKR_BUFFER_TOO_SMALL => Pkcs11Error::BufferTooSmall,
            CKR_SAVED_STATE_INVALID => Pkcs11Error::SavedStateInvalid,
            CKR_INFORMATION_SENSITIVE => Pkcs11Error::InformationSensitive,
            CKR_STATE_UNSAVEABLE => Pkcs11Error::StateUnsaveable,
            CKR_CRYPTOKI_NOT_INITIALIZED => Pkcs11Error::CryptokiNotInitialized,
            CKR_CRYPTOKI_ALREADY_INITIALIZED => Pkcs11Error::CryptokiAlreadyInitialized,
            CKR_MUTEX_BAD => Pkcs11Error::MutexBad,
            CKR_MUTEX_NOT_LOCKED => Pkcs11Error::MutexNotLocked,
            CKR_NEW_PIN_MODE => Pkcs11Error::NewPinMode,
            CKR_NEXT_OTP => Pkcs11Error::NextOtp,
            CKR_EXCEEDED_MAX_ITERATIONS => Pkcs11Error::ExceededMaxIterations,
            CKR_FIPS_SELF_TEST_FAILED => Pkcs11Error::FipsSelfTestFailed,
            CKR_LIBRARY_LOAD_FAILED => Pkcs11Error::LibraryLoadFailed,
            CKR_PIN_TOO_WEAK => Pkcs11Error::PinTooWeak,
            CKR_PUBLIC_KEY_INVALID => Pkcs11Error::PublicKeyInvalid,
            CKR_FUNCTION_REJECTED => Pkcs11Error::FunctionRejected,
            CKR_VENDOR_DEFINED => Pkcs11Error::VendorDefined,
            _ => Pkcs11Error::Unknown,
        }
    }
}

/// todo: implement this for real
impl fmt::Display for Pkcs11Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            _ => write!(f, "{:?}", self),
        }
    }
}

macro_rules! r#try_ck {
    ($name:tt,$expr:expr) => {
        match $expr as u32 {
            pkcs11_sys::CKR_OK => {
                log::trace!("{} succeeded", $name);
            }
            err => {
                log::trace!(
                    "{} failed with {}",
                    $name,
                    $crate::error::Pkcs11Error::from(err.into())
                );
                return Err(From::from($crate::error::ErrorKind::Function(
                    $name,
                    $crate::error::Pkcs11Error::from(err.into()),
                )));
            }
        }
    };
    ($name:tt,$expr:expr,) => {
        r#try_ck!($expr)
    };
}
