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
