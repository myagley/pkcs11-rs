use pkcs11_sys::*;

/// A value that identifies a hardware feature type of a device.
///
/// Hardware feature types are defined with the objects that use them. The type
/// is specified on an object through the CKA_HW_FEATURE_TYPE attribute of the
/// object.
///
/// Vendor defined values for this type may also be specified.
#[derive(Debug, PartialEq)]
pub enum HwFeatureType {
    Clock,
    MonotonicCounter,
    UserInterface,
    Vendor,
}

impl From<HwFeatureType> for CK_HW_FEATURE_TYPE {
    fn from(hw_feature_type: HwFeatureType) -> CK_HW_FEATURE_TYPE {
        match hw_feature_type {
            HwFeatureType::Vendor => CKH_VENDOR_DEFINED as CK_HW_FEATURE_TYPE,
            HwFeatureType::Clock => CKH_CLOCK as CK_HW_FEATURE_TYPE,
            HwFeatureType::MonotonicCounter => CKH_MONOTONIC_COUNTER as CK_HW_FEATURE_TYPE,
            HwFeatureType::UserInterface => CKH_USER_INTERFACE as CK_HW_FEATURE_TYPE,
        }
    }
}
