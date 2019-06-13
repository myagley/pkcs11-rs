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
    #[fail(display = "Function error: \"{}\"", _0)]
    Function(FunctionErrorReason),
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
pub enum FunctionErrorReason {
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

impl FunctionErrorReason {
    pub(crate) fn from(rv: CK_RV) -> FunctionErrorReason {
        match rv as u32 {
            CKR_CANCEL => FunctionErrorReason::Cancel,
            CKR_HOST_MEMORY => FunctionErrorReason::HostMemory,
            CKR_SLOT_ID_INVALID => FunctionErrorReason::SlotIdInvalid,
            CKR_GENERAL_ERROR => FunctionErrorReason::GeneralError,
            CKR_FUNCTION_FAILED => FunctionErrorReason::FunctionFailed,
            CKR_ARGUMENTS_BAD => FunctionErrorReason::ArgumentsBad,
            CKR_NO_EVENT => FunctionErrorReason::NoEvent,
            CKR_NEED_TO_CREATE_THREADS => FunctionErrorReason::NeedToCreateThreads,
            CKR_CANT_LOCK => FunctionErrorReason::CantLock,
            CKR_ATTRIBUTE_READ_ONLY => FunctionErrorReason::AttributeReadOnly,
            CKR_ATTRIBUTE_SENSITIVE => FunctionErrorReason::AttributeSensitive,
            CKR_ATTRIBUTE_TYPE_INVALID => FunctionErrorReason::AttributeTypeInvalid,
            CKR_ATTRIBUTE_VALUE_INVALID => FunctionErrorReason::AttributeValueInvalid,
            CKR_ACTION_PROHIBITED => FunctionErrorReason::ActionProhibited,
            CKR_DATA_INVALID => FunctionErrorReason::DataInvalid,
            CKR_DATA_LEN_RANGE => FunctionErrorReason::DataLenRange,
            CKR_DEVICE_ERROR => FunctionErrorReason::DeviceError,
            CKR_DEVICE_MEMORY => FunctionErrorReason::DeviceMemory,
            CKR_DEVICE_REMOVED => FunctionErrorReason::DeviceRemoved,
            CKR_ENCRYPTED_DATA_INVALID => FunctionErrorReason::EncryptedDataInvalid,
            CKR_ENCRYPTED_DATA_LEN_RANGE => FunctionErrorReason::EncryptedDataLenRange,
            CKR_FUNCTION_CANCELED => FunctionErrorReason::FunctionCanceled,
            CKR_FUNCTION_NOT_PARALLEL => FunctionErrorReason::FunctionNotParallel,
            CKR_FUNCTION_NOT_SUPPORTED => FunctionErrorReason::FunctionNotSupported,
            CKR_KEY_HANDLE_INVALID => FunctionErrorReason::KeyHandleInvalid,
            CKR_KEY_SIZE_RANGE => FunctionErrorReason::KeySizeRange,
            CKR_KEY_TYPE_INCONSISTENT => FunctionErrorReason::KeyTypeInconsistent,
            CKR_KEY_NOT_NEEDED => FunctionErrorReason::KeyNotNeeded,
            CKR_KEY_CHANGED => FunctionErrorReason::KeyChanged,
            CKR_KEY_NEEDED => FunctionErrorReason::KeyNeeded,
            CKR_KEY_INDIGESTIBLE => FunctionErrorReason::KeyIndigestible,
            CKR_KEY_FUNCTION_NOT_PERMITTED => FunctionErrorReason::KeyFunctionNotPermitted,
            CKR_KEY_NOT_WRAPPABLE => FunctionErrorReason::KeyNotWrappable,
            CKR_KEY_UNEXTRACTABLE => FunctionErrorReason::KeyUnextractable,
            CKR_MECHANISM_INVALID => FunctionErrorReason::MechanismInvalid,
            CKR_MECHANISM_PARAM_INVALID => FunctionErrorReason::MechanismParamInvalid,
            CKR_OBJECT_HANDLE_INVALID => FunctionErrorReason::ObjectHandleInvalid,
            CKR_OPERATION_ACTIVE => FunctionErrorReason::OperationActive,
            CKR_OPERATION_NOT_INITIALIZED => FunctionErrorReason::OperationNotInitialized,
            CKR_PIN_INCORRECT => FunctionErrorReason::PinIncorrect,
            CKR_PIN_INVALID => FunctionErrorReason::PinInvalid,
            CKR_PIN_LEN_RANGE => FunctionErrorReason::PinLenRange,
            CKR_PIN_EXPIRED => FunctionErrorReason::PinExpired,
            CKR_PIN_LOCKED => FunctionErrorReason::PinLocked,
            CKR_SESSION_CLOSED => FunctionErrorReason::SessionClosed,
            CKR_SESSION_COUNT => FunctionErrorReason::SessionCount,
            CKR_SESSION_HANDLE_INVALID => FunctionErrorReason::SessionHandleInvalid,
            CKR_SESSION_PARALLEL_NOT_SUPPORTED => FunctionErrorReason::SessionParallelNotSupported,
            CKR_SESSION_READ_ONLY => FunctionErrorReason::SessionReadOnly,
            CKR_SESSION_EXISTS => FunctionErrorReason::SessionExists,
            CKR_SESSION_READ_ONLY_EXISTS => FunctionErrorReason::SessionReadOnlyExists,
            CKR_SESSION_READ_WRITE_SO_EXISTS => FunctionErrorReason::SessionReadWriteSoExists,
            CKR_SIGNATURE_INVALID => FunctionErrorReason::SignatureInvalid,
            CKR_SIGNATURE_LEN_RANGE => FunctionErrorReason::SignatureLenRange,
            CKR_TEMPLATE_INCOMPLETE => FunctionErrorReason::TemplateIncomplete,
            CKR_TEMPLATE_INCONSISTENT => FunctionErrorReason::TemplateInconsistent,
            CKR_TOKEN_NOT_PRESENT => FunctionErrorReason::TokenNotPresent,
            CKR_TOKEN_NOT_RECOGNIZED => FunctionErrorReason::TokenNotRecognized,
            CKR_TOKEN_WRITE_PROTECTED => FunctionErrorReason::TokenWriteProtected,
            CKR_UNWRAPPING_KEY_HANDLE_INVALID => FunctionErrorReason::UnwrappingKeyHandleInvalid,
            CKR_UNWRAPPING_KEY_SIZE_RANGE => FunctionErrorReason::UnwrappingKeySizeRange,
            CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT => {
                FunctionErrorReason::UnwrappingKeyTypeInconsistent
            }
            CKR_USER_ALREADY_LOGGED_IN => FunctionErrorReason::UserAlreadyLoggedIn,
            CKR_USER_NOT_LOGGED_IN => FunctionErrorReason::UserNotLoggedIn,
            CKR_USER_PIN_NOT_INITIALIZED => FunctionErrorReason::UserPinNotInitialized,
            CKR_USER_TYPE_INVALID => FunctionErrorReason::UserTypeInvalid,
            CKR_USER_ANOTHER_ALREADY_LOGGED_IN => FunctionErrorReason::UserAnotherAlreadyLoggedIn,
            CKR_USER_TOO_MANY_TYPES => FunctionErrorReason::UserTooManyTypes,
            CKR_WRAPPED_KEY_INVALID => FunctionErrorReason::WrappedKeyInvalid,
            CKR_WRAPPED_KEY_LEN_RANGE => FunctionErrorReason::WrappedKeyLenRange,
            CKR_WRAPPING_KEY_HANDLE_INVALID => FunctionErrorReason::WrappingKeyHandleInvalid,
            CKR_WRAPPING_KEY_SIZE_RANGE => FunctionErrorReason::WrappingKeySizeRange,
            CKR_WRAPPING_KEY_TYPE_INCONSISTENT => FunctionErrorReason::WrappingKeyTypeInconsistent,
            CKR_RANDOM_SEED_NOT_SUPPORTED => FunctionErrorReason::RandomSeedNotSupported,
            CKR_RANDOM_NO_RNG => FunctionErrorReason::RandomNoRng,
            CKR_DOMAIN_PARAMS_INVALID => FunctionErrorReason::DomainParamsInvalid,
            CKR_CURVE_NOT_SUPPORTED => FunctionErrorReason::CurveNotSupported,
            CKR_BUFFER_TOO_SMALL => FunctionErrorReason::BufferTooSmall,
            CKR_SAVED_STATE_INVALID => FunctionErrorReason::SavedStateInvalid,
            CKR_INFORMATION_SENSITIVE => FunctionErrorReason::InformationSensitive,
            CKR_STATE_UNSAVEABLE => FunctionErrorReason::StateUnsaveable,
            CKR_CRYPTOKI_NOT_INITIALIZED => FunctionErrorReason::CryptokiNotInitialized,
            CKR_CRYPTOKI_ALREADY_INITIALIZED => FunctionErrorReason::CryptokiAlreadyInitialized,
            CKR_MUTEX_BAD => FunctionErrorReason::MutexBad,
            CKR_MUTEX_NOT_LOCKED => FunctionErrorReason::MutexNotLocked,
            CKR_NEW_PIN_MODE => FunctionErrorReason::NewPinMode,
            CKR_NEXT_OTP => FunctionErrorReason::NextOtp,
            CKR_EXCEEDED_MAX_ITERATIONS => FunctionErrorReason::ExceededMaxIterations,
            CKR_FIPS_SELF_TEST_FAILED => FunctionErrorReason::FipsSelfTestFailed,
            CKR_LIBRARY_LOAD_FAILED => FunctionErrorReason::LibraryLoadFailed,
            CKR_PIN_TOO_WEAK => FunctionErrorReason::PinTooWeak,
            CKR_PUBLIC_KEY_INVALID => FunctionErrorReason::PublicKeyInvalid,
            CKR_FUNCTION_REJECTED => FunctionErrorReason::FunctionRejected,
            CKR_VENDOR_DEFINED => FunctionErrorReason::VendorDefined,
            _ => FunctionErrorReason::Unknown,
        }
    }
}

/// todo: implement this for real
impl fmt::Display for FunctionErrorReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            _ => write!(f, "unknown"),
        }
    }
}

macro_rules! r#try_ck {
    ($expr:expr) => {
        match $expr as u32 {
            pkcs11_sys::CKR_OK => (),
            err => {
                return Err(From::from($crate::error::ErrorKind::Function(
                    $crate::error::FunctionErrorReason::from(err.into()),
                )))
            }
        }
    };
    ($expr:expr,) => {
        r#try_ck!($expr)
    };
}
