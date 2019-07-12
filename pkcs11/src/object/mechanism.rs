use std::ffi::c_void;
use std::fmt;

use bitflags::bitflags;
use pkcs11_sys::*;

pub trait Mechanism {
    fn r#type(&self) -> MechanismType;
    fn as_ptr(&self) -> *const c_void;
    fn len(&self) -> CK_ULONG;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

bitflags! {
    /// Bit flags specifying mechanism capabilities.
    pub struct MechanismFlags: CK_FLAGS {
        const HW = CKF_HW as CK_FLAGS;
        const ENCRYPT = CKF_ENCRYPT as CK_FLAGS;
        const DECRYPT = CKF_DECRYPT as CK_FLAGS;
        const DIGEST = CKF_DIGEST as CK_FLAGS;
        const SIGN = CKF_SIGN as CK_FLAGS;
        const SIGN_RECOVER = CKF_SIGN_RECOVER as CK_FLAGS;
        const VERIFY = CKF_VERIFY as CK_FLAGS;
        const VERIFY_RECOVER = CKF_VERIFY_RECOVER as CK_FLAGS;
        const GENERATE = CKF_GENERATE as CK_FLAGS;
        const GENERATE_KEY_PAIR = CKF_GENERATE_KEY_PAIR as CK_FLAGS;
        const WRAP = CKF_WRAP as CK_FLAGS;
        const UNWRAP = CKF_UNWRAP as CK_FLAGS;
        const DERIVE = CKF_DERIVE as CK_FLAGS;
        const EXTENSION = CKF_EXTENSION as CK_FLAGS;
    }
}

pub struct MechanismInfo {
    pub(crate) inner: CK_MECHANISM_INFO,
}

impl MechanismInfo {
    pub fn min_key_size(&self) -> CK_ULONG {
        self.inner.ulMinKeySize
    }

    pub fn max_key_size(&self) -> CK_ULONG {
        self.inner.ulMaxKeySize
    }

    pub fn flags(&self) -> MechanismFlags {
        MechanismFlags::from_bits_truncate(self.inner.flags)
    }
}

impl fmt::Debug for MechanismInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut d = f.debug_struct("MechanismInfo");
        d.field("flags", &self.flags());
        d.field("min_key_size", &self.min_key_size());
        d.field("max_key_size", &self.max_key_size());
        d.finish()
    }
}

#[derive(Debug)]
pub struct RsaPkcsPssParams {
    type_: MechanismType,
    inner: CK_RSA_PKCS_PSS_PARAMS,
}

impl Mechanism for RsaPkcsPssParams {
    fn r#type(&self) -> MechanismType {
        self.type_
    }

    fn as_ptr(&self) -> *const c_void {
        &self.inner as *const _ as *const c_void
    }

    fn len(&self) -> CK_ULONG {
        std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG
    }
}

impl<'a> Mechanism for &'a RsaPkcsPssParams {
    fn r#type(&self) -> MechanismType {
        self.type_
    }

    fn as_ptr(&self) -> *const c_void {
        &self.inner as *const _ as *const c_void
    }

    fn len(&self) -> CK_ULONG {
        std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG
    }
}

pub static MECH_RSA_PSS_SHA256: RsaPkcsPssParams = RsaPkcsPssParams {
    type_: MechanismType::RsaPkcsPss,
    inner: CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA256 as CK_MECHANISM_TYPE,
        mgf: CKG_MGF1_SHA256 as CK_RSA_PKCS_MGF_TYPE,
        sLen: 32,
    },
};

pub static MECH_RSA_PSS_SHA384: RsaPkcsPssParams = RsaPkcsPssParams {
    type_: MechanismType::RsaPkcsPss,
    inner: CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA384 as CK_MECHANISM_TYPE,
        mgf: CKG_MGF1_SHA384 as CK_RSA_PKCS_MGF_TYPE,
        sLen: 48,
    },
};

pub static MECH_RSA_PSS_SHA512: RsaPkcsPssParams = RsaPkcsPssParams {
    type_: MechanismType::RsaPkcsPss,
    inner: CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA512 as CK_MECHANISM_TYPE,
        mgf: CKG_MGF1_SHA512 as CK_RSA_PKCS_MGF_TYPE,
        sLen: 64,
    },
};

/// A value that identifies a mechanism type.
///
/// Mechanism types are defined with the objects and mechanism descriptions that
/// use them.
///
/// Vendor defined values for this type may also be specified.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum MechanismType {
    Acti,
    ActiKeyGen,
    AesCbc,
    AesCbcEncryptData,
    AesCbcPad,
    AesCcm,
    AesCfb1,
    AesCfb8,
    AesCfb64,
    AesCfb128,
    AesCmac,
    AesCmacGeneral,
    AesCtr,
    AesCts,
    AesEcb,
    AesEcbEncryptData,
    AesGcm,
    AesGmac,
    AesKeyGen,
    AesKeyWrap,
    AesKeyWrapPad,
    AesMac,
    AesMacGeneral,
    AesOfb,
    AesXcbcMac,
    AesXcbcMac96,
    AriaCbc,
    AriaCbcEncryptData,
    AriaCbcPad,
    AriaEcb,
    AriaEcbEncryptData,
    AriaKeyGen,
    AriaMac,
    AriaMacGeneral,
    BatonCbc128,
    BatonCounter,
    BatonEcb96,
    BatonEcb128,
    BatonKeyGen,
    BatonShuffle,
    BatonWrap,
    BlowfishCbc,
    BlowfishCbcPad,
    BlowfishKeyGen,
    CamelliaCbc,
    CamelliaCbcEncryptData,
    CamelliaCbcPad,
    CamelliaCtr,
    CamelliaEcb,
    CamelliaEcbEncryptData,
    CamelliaKeyGen,
    CamelliaMac,
    CamelliaMacGeneral,
    Cast3KeyGen,
    Cast3Ecb,
    Cast3Cbc,
    Cast3Mac,
    Cast3MacGeneral,
    Cast3CbcPad,
    Cast5KeyGen,
    Cast5Ecb,
    Cast5Cbc,
    Cast5Mac,
    Cast5MacGeneral,
    Cast5CbcPad,
    Cast128KeyGen,
    Cast128Ecb,
    Cast128Cbc,
    Cast128Mac,
    Cast128MacGeneral,
    Cast128CbcPad,
    CastCbc,
    CastCbcPad,
    CastEcb,
    CastKeyGen,
    CastMac,
    CastMacGeneral,
    CdmfCbc,
    CdmfCbcPad,
    CdmfEcb,
    CdmfKeyGen,
    CdmfMac,
    CdmfMacGeneral,
    CmsSig,
    ConcatenateBaseAndData,
    ConcatenateBaseAndKey,
    ConcatenateDataAndBase,
    Des2KeyGen,
    Des3KeyGen,
    Des3Ecb,
    Des3Cbc,
    Des3Mac,
    Des3MacGeneral,
    Des3CbcPad,
    Des3CmacGeneral,
    Des3Cmac,
    Des3EcbEncryptData,
    Des3CbcEncryptData,
    DesCbc,
    DesCbcEncryptData,
    DesCbcPad,
    DesCfb8,
    DesCfb64,
    DesEcb,
    DesEcbEncryptData,
    DesKeyGen,
    DesMac,
    DesMacGeneral,
    DesOfb8,
    DesOfb64,
    DhPkcsDerive,
    DhPkcsKeyPairGen,
    DhPkcsParameterGen,
    Dsa,
    DsaKeyPairGen,
    DsaParameterGen,
    DsaProbablisticParameterGen,
    DsaSha1,
    DsaSha224,
    DsaSha256,
    DsaSha384,
    DsaSha512,
    DsaShaweTaylorParameterGen,
    Ecdh1Derive,
    Ecdh1CofactorDerive,
    EcdhAesKeyWrap,
    Ecdsa,
    EcdsaKeyPairGen,
    EcdsaSha1,
    EcdsaSha224,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    EcmqvDerive,
    EcKeyPairGen,
    ExtractKeyFromKey,
    Fasthash,
    FortezzaTimestamp,
    GenericSecretKeyGen,
    Gost28147KeyGen,
    Gost28147Ecb,
    Gost28147,
    Gost28147Mac,
    Gost28147KeyWrap,
    Gostr3410KeyPairGen,
    Gostr3410,
    Gostr3410KeyWrap,
    Gostr3410Derive,
    Gostr3411,
    Gostr3411Hmac,
    Gostr3410WithGostr3411,
    Hotp,
    HotpKeyGen,
    IdeaCbc,
    IdeaCbcPad,
    IdeaEcb,
    IdeaKeyGen,
    IdeaMac,
    IdeaMacGeneral,
    JuniperCbc128,
    JuniperCounter,
    JuniperEcb128,
    JuniperKeyGen,
    JuniperShuffle,
    JuniperWrap,
    KeaDerive,
    KeaKeyDerive,
    KeaKeyPairGen,
    KeyWrapLynks,
    KeyWrapSetOaep,
    KipDerive,
    KipMac,
    KipWrap,
    Md2RsaPkcs,
    Md2,
    Md2Hmac,
    Md2HmacGeneral,
    Md2KeyDerivation,
    Md5RsaPkcs,
    Md5,
    Md5Hmac,
    Md5HmacGeneral,
    Md5KeyDerivation,
    PbaSha1WithSha1Hmac,
    PbeMd2DesCbc,
    PbeMd5DesCbc,
    PbeMd5CastCbc,
    PbeMd5Cast3Cbc,
    PbeMd5Cast5Cbc,
    PbeMd5Cast128Cbc,
    PbeSha1Cast5Cbc,
    PbeSha1Cast128Cbc,
    PbeSha1Des2EdeCbc,
    PbeSha1Des3EdeCbc,
    PbeSha1Rc2_40Cbc,
    PbeSha1Rc2_128Cbc,
    PbeSha1Rc4_40,
    PbeSha1Rc4_128,
    Pkcs5Pbkd2,
    Rc2KeyGen,
    Rc2Ecb,
    Rc2Cbc,
    Rc2Mac,
    Rc2MacGeneral,
    Rc2CbcPad,
    Rc4KeyGen,
    Rc4,
    Rc5KeyGen,
    Rc5Ecb,
    Rc5Cbc,
    Rc5Mac,
    Rc5MacGeneral,
    Rrc5CbcPad,
    Ripemd128RsaPkcs,
    Ripemd128,
    Ripemd128Hmac,
    Ripemd128HmacGeneral,
    Ripemd160RsaPkcs,
    Ripemd160,
    Ripemd160Hmac,
    Ripemd160HmacGeneral,
    Rsa9796,
    RsaAesKeyWrap,
    RsaPkcs,
    RsaPkcsKeyPairGen,
    RsaPkcsOaep,
    RsaPkcsOaepTpm11,
    RsaPkcsPss,
    RsaPkcsTpm11,
    RsaX9_31KeyPairGen,
    RsaX9_31,
    RsaX509,
    Securid,
    SecuridKeyGen,
    SeedCbc,
    SeedCbcEncryptData,
    SeedCbcPad,
    SeedEcb,
    SeedEcbEncryptData,
    SeedKeyGen,
    SeedMac,
    SeedMacGeneral,
    Sha1RsaPkcs,
    Sha1RsaPkcsPss,
    Sha1KeyDerivation,
    Sha224RsaPkcs,
    Sha224RsaPkcsPss,
    Sha224,
    Sha224Hmac,
    Sha224HmacGeneral,
    Sha224KeyDerivation,
    Sha256RsaPkcs,
    Sha256RsaPkcsPss,
    Sha256,
    Sha256Hmac,
    Sha256HmacGeneral,
    Sha256KeyDerivation,
    Sha384RsaPkcs,
    Sha384RsaPkcsPss,
    Sha384,
    Sha384Hmac,
    Sha384HmacGeneral,
    Sha384KeyDerivation,
    Sha512RsaPkcs,
    Sha512RsaPkcsPss,
    Sha512T,
    Sha512THmac,
    Sha512THmacGeneral,
    Sha512TKeyDerivation,
    Sha512,
    Sha512Hmac,
    Sha512HmacGeneral,
    Sha512KeyDerivation,
    Sha1RsaX9_31,
    Sha512_224,
    Sha512_224Hmac,
    Sha512_224HmacGeneral,
    Sha512_224KeyDerivation,
    Sha512_256,
    Sha512_256Hmac,
    Sha512_256HmacGeneral,
    Sha512_256KeyDerivation,
    Sha1,
    Sha1Hmac,
    Sha1HmacGeneral,
    SkipjackCbc64,
    SkipjackCfb8,
    SkipjackCfb16,
    SkipjackCfb32,
    SkipjackCfb64,
    SkipjackEcb64,
    SkipjackKeyGen,
    SkipjackOfb64,
    SkipjackPrivateWrap,
    SkipjackRelayx,
    SkipjackWrap,
    Ssl3PreMasterKeyGen,
    Ssl3MasterKeyDerive,
    Ssl3KeyAndMacDerive,
    Ssl3MasterKeyDeriveDh,
    Ssl3Md5Mac,
    Ssl3Sha1Mac,
    Tls10MacServer,
    Tls10MacClient,
    Tls12Mac,
    Tls12Kdf,
    Tls12MasterKeyDerive,
    Tls12KeyAndMacDerive,
    Tls12MasterKeyDeriveDh,
    Tls12KeySafeDerive,
    TlsKdf,
    TlsKeyAndMacDerive,
    TlsMac,
    TlsMasterKeyDerive,
    TlsMasterKeyDeriveDh,
    TlsPreMasterKeyGen,
    TlsPrf,
    TwofishCbc,
    TwofishCbcPad,
    TwofishKeyGen,
    VendorDefined,
    WtlsClientKeyAndMacDerive,
    WtlsMasterKeyDerive,
    WtlsMasterKeyDeriveDhEcc,
    WtlsPreMasterKeyGen,
    WtlsPrf,
    WtlsServerKeyAndMacDerive,
    X9_42DhKeyPairGen,
    X9_42DhDerive,
    X9_42DhHybridDerive,
    X9_42MqvDerive,
    X9_42DhParameterGen,
    XorBaseAndData,
}

impl Mechanism for MechanismType {
    fn r#type(&self) -> MechanismType {
        *self
    }

    fn as_ptr(&self) -> *const c_void {
        std::ptr::null()
    }

    fn len(&self) -> CK_ULONG {
        0
    }
}

impl From<MechanismType> for CK_MECHANISM_TYPE {
    fn from(mechanism_type: MechanismType) -> CK_MECHANISM_TYPE {
        match mechanism_type {
            MechanismType::Acti => CK_MECHANISM_TYPE::from(CKM_ACTI),
            MechanismType::ActiKeyGen => CK_MECHANISM_TYPE::from(CKM_ACTI_KEY_GEN),
            MechanismType::AesCbc => CK_MECHANISM_TYPE::from(CKM_AES_CBC),
            MechanismType::AesCbcEncryptData => CK_MECHANISM_TYPE::from(CKM_AES_CBC_ENCRYPT_DATA),
            MechanismType::AesCbcPad => CK_MECHANISM_TYPE::from(CKM_AES_CBC_PAD),
            MechanismType::AesCcm => CK_MECHANISM_TYPE::from(CKM_AES_CCM),
            MechanismType::AesCfb1 => CK_MECHANISM_TYPE::from(CKM_AES_CFB1),
            MechanismType::AesCfb8 => CK_MECHANISM_TYPE::from(CKM_AES_CFB8),
            MechanismType::AesCfb64 => CK_MECHANISM_TYPE::from(CKM_AES_CFB64),
            MechanismType::AesCfb128 => CK_MECHANISM_TYPE::from(CKM_AES_CFB128),
            MechanismType::AesCmac => CK_MECHANISM_TYPE::from(CKM_AES_CMAC),
            MechanismType::AesCmacGeneral => CK_MECHANISM_TYPE::from(CKM_AES_CMAC_GENERAL),
            MechanismType::AesCtr => CK_MECHANISM_TYPE::from(CKM_AES_CTR),
            MechanismType::AesCts => CK_MECHANISM_TYPE::from(CKM_AES_CTS),
            MechanismType::AesEcb => CK_MECHANISM_TYPE::from(CKM_AES_ECB),
            MechanismType::AesEcbEncryptData => CK_MECHANISM_TYPE::from(CKM_AES_ECB_ENCRYPT_DATA),
            MechanismType::AesGcm => CK_MECHANISM_TYPE::from(CKM_AES_GCM),
            MechanismType::AesGmac => CK_MECHANISM_TYPE::from(CKM_AES_GMAC),
            MechanismType::AesKeyGen => CK_MECHANISM_TYPE::from(CKM_AES_KEY_GEN),
            MechanismType::AesKeyWrap => CK_MECHANISM_TYPE::from(CKM_AES_KEY_WRAP),
            MechanismType::AesKeyWrapPad => CK_MECHANISM_TYPE::from(CKM_AES_KEY_WRAP_PAD),
            MechanismType::AesMac => CK_MECHANISM_TYPE::from(CKM_AES_MAC),
            MechanismType::AesMacGeneral => CK_MECHANISM_TYPE::from(CKM_AES_MAC_GENERAL),
            MechanismType::AesOfb => CK_MECHANISM_TYPE::from(CKM_AES_OFB),
            MechanismType::AesXcbcMac => CK_MECHANISM_TYPE::from(CKM_AES_XCBC_MAC),
            MechanismType::AesXcbcMac96 => CK_MECHANISM_TYPE::from(CKM_AES_XCBC_MAC_96),
            MechanismType::AriaCbc => CK_MECHANISM_TYPE::from(CKM_ARIA_CBC),
            MechanismType::AriaCbcEncryptData => CK_MECHANISM_TYPE::from(CKM_ARIA_CBC_ENCRYPT_DATA),
            MechanismType::AriaCbcPad => CK_MECHANISM_TYPE::from(CKM_ARIA_CBC_PAD),
            MechanismType::AriaEcb => CK_MECHANISM_TYPE::from(CKM_ARIA_ECB),
            MechanismType::AriaEcbEncryptData => CK_MECHANISM_TYPE::from(CKM_ARIA_ECB_ENCRYPT_DATA),
            MechanismType::AriaKeyGen => CK_MECHANISM_TYPE::from(CKM_ARIA_KEY_GEN),
            MechanismType::AriaMac => CK_MECHANISM_TYPE::from(CKM_ARIA_MAC),
            MechanismType::AriaMacGeneral => CK_MECHANISM_TYPE::from(CKM_ARIA_MAC_GENERAL),
            MechanismType::BatonCbc128 => CK_MECHANISM_TYPE::from(CKM_BATON_CBC128),
            MechanismType::BatonCounter => CK_MECHANISM_TYPE::from(CKM_BATON_COUNTER),
            MechanismType::BatonEcb96 => CK_MECHANISM_TYPE::from(CKM_BATON_ECB96),
            MechanismType::BatonEcb128 => CK_MECHANISM_TYPE::from(CKM_BATON_ECB128),
            MechanismType::BatonKeyGen => CK_MECHANISM_TYPE::from(CKM_BATON_KEY_GEN),
            MechanismType::BatonShuffle => CK_MECHANISM_TYPE::from(CKM_BATON_SHUFFLE),
            MechanismType::BatonWrap => CK_MECHANISM_TYPE::from(CKM_BATON_WRAP),
            MechanismType::BlowfishCbc => CK_MECHANISM_TYPE::from(CKM_BLOWFISH_CBC),
            MechanismType::BlowfishCbcPad => CK_MECHANISM_TYPE::from(CKM_BLOWFISH_CBC_PAD),
            MechanismType::BlowfishKeyGen => CK_MECHANISM_TYPE::from(CKM_BLOWFISH_KEY_GEN),
            MechanismType::CamelliaCbc => CK_MECHANISM_TYPE::from(CKM_CAMELLIA_CBC),
            MechanismType::CamelliaCbcEncryptData => {
                CK_MECHANISM_TYPE::from(CKM_CAMELLIA_CBC_ENCRYPT_DATA)
            }
            MechanismType::CamelliaCbcPad => CK_MECHANISM_TYPE::from(CKM_CAMELLIA_CBC_PAD),
            MechanismType::CamelliaCtr => CK_MECHANISM_TYPE::from(CKM_CAMELLIA_CTR),
            MechanismType::CamelliaEcb => CK_MECHANISM_TYPE::from(CKM_CAMELLIA_ECB),
            MechanismType::CamelliaEcbEncryptData => {
                CK_MECHANISM_TYPE::from(CKM_CAMELLIA_ECB_ENCRYPT_DATA)
            }
            MechanismType::CamelliaKeyGen => CK_MECHANISM_TYPE::from(CKM_CAMELLIA_KEY_GEN),
            MechanismType::CamelliaMac => CK_MECHANISM_TYPE::from(CKM_CAMELLIA_MAC),
            MechanismType::CamelliaMacGeneral => CK_MECHANISM_TYPE::from(CKM_CAMELLIA_MAC_GENERAL),
            MechanismType::Cast3KeyGen => CK_MECHANISM_TYPE::from(CKM_CAST3_KEY_GEN),
            MechanismType::Cast3Ecb => CK_MECHANISM_TYPE::from(CKM_CAST3_ECB),
            MechanismType::Cast3Cbc => CK_MECHANISM_TYPE::from(CKM_CAST3_CBC),
            MechanismType::Cast3Mac => CK_MECHANISM_TYPE::from(CKM_CAST3_MAC),
            MechanismType::Cast3MacGeneral => CK_MECHANISM_TYPE::from(CKM_CAST3_MAC_GENERAL),
            MechanismType::Cast3CbcPad => CK_MECHANISM_TYPE::from(CKM_CAST3_CBC_PAD),
            MechanismType::Cast5KeyGen => CK_MECHANISM_TYPE::from(CKM_CAST5_KEY_GEN),
            MechanismType::Cast5Ecb => CK_MECHANISM_TYPE::from(CKM_CAST5_ECB),
            MechanismType::Cast5Cbc => CK_MECHANISM_TYPE::from(CKM_CAST5_CBC),
            MechanismType::Cast5Mac => CK_MECHANISM_TYPE::from(CKM_CAST5_MAC),
            MechanismType::Cast5MacGeneral => CK_MECHANISM_TYPE::from(CKM_CAST5_MAC_GENERAL),
            MechanismType::Cast5CbcPad => CK_MECHANISM_TYPE::from(CKM_CAST5_CBC_PAD),
            MechanismType::Cast128KeyGen => CK_MECHANISM_TYPE::from(CKM_CAST128_KEY_GEN),
            MechanismType::Cast128Ecb => CK_MECHANISM_TYPE::from(CKM_CAST128_ECB),
            MechanismType::Cast128Cbc => CK_MECHANISM_TYPE::from(CKM_CAST128_CBC),
            MechanismType::Cast128Mac => CK_MECHANISM_TYPE::from(CKM_CAST128_MAC),
            MechanismType::Cast128MacGeneral => CK_MECHANISM_TYPE::from(CKM_CAST128_MAC_GENERAL),
            MechanismType::Cast128CbcPad => CK_MECHANISM_TYPE::from(CKM_CAST128_CBC_PAD),
            MechanismType::CastCbc => CK_MECHANISM_TYPE::from(CKM_CAST_CBC),
            MechanismType::CastCbcPad => CK_MECHANISM_TYPE::from(CKM_CAST_CBC_PAD),
            MechanismType::CastEcb => CK_MECHANISM_TYPE::from(CKM_CAST_ECB),
            MechanismType::CastKeyGen => CK_MECHANISM_TYPE::from(CKM_CAST_KEY_GEN),
            MechanismType::CastMac => CK_MECHANISM_TYPE::from(CKM_CAST_MAC),
            MechanismType::CastMacGeneral => CK_MECHANISM_TYPE::from(CKM_CAST_MAC_GENERAL),
            MechanismType::CdmfCbc => CK_MECHANISM_TYPE::from(CKM_CDMF_CBC),
            MechanismType::CdmfCbcPad => CK_MECHANISM_TYPE::from(CKM_CDMF_CBC_PAD),
            MechanismType::CdmfEcb => CK_MECHANISM_TYPE::from(CKM_CDMF_ECB),
            MechanismType::CdmfKeyGen => CK_MECHANISM_TYPE::from(CKM_CDMF_KEY_GEN),
            MechanismType::CdmfMac => CK_MECHANISM_TYPE::from(CKM_CDMF_MAC),
            MechanismType::CdmfMacGeneral => CK_MECHANISM_TYPE::from(CKM_CDMF_MAC_GENERAL),
            MechanismType::CmsSig => CK_MECHANISM_TYPE::from(CKM_CMS_SIG),
            MechanismType::ConcatenateBaseAndData => {
                CK_MECHANISM_TYPE::from(CKM_CONCATENATE_BASE_AND_DATA)
            }
            MechanismType::ConcatenateBaseAndKey => {
                CK_MECHANISM_TYPE::from(CKM_CONCATENATE_BASE_AND_KEY)
            }
            MechanismType::ConcatenateDataAndBase => {
                CK_MECHANISM_TYPE::from(CKM_CONCATENATE_DATA_AND_BASE)
            }
            MechanismType::Des2KeyGen => CK_MECHANISM_TYPE::from(CKM_DES2_KEY_GEN),
            MechanismType::Des3KeyGen => CK_MECHANISM_TYPE::from(CKM_DES3_KEY_GEN),
            MechanismType::Des3Ecb => CK_MECHANISM_TYPE::from(CKM_DES3_ECB),
            MechanismType::Des3Cbc => CK_MECHANISM_TYPE::from(CKM_DES3_CBC),
            MechanismType::Des3Mac => CK_MECHANISM_TYPE::from(CKM_DES3_MAC),
            MechanismType::Des3MacGeneral => CK_MECHANISM_TYPE::from(CKM_DES3_MAC_GENERAL),
            MechanismType::Des3CbcPad => CK_MECHANISM_TYPE::from(CKM_DES3_CBC_PAD),
            MechanismType::Des3CmacGeneral => CK_MECHANISM_TYPE::from(CKM_DES3_CMAC_GENERAL),
            MechanismType::Des3Cmac => CK_MECHANISM_TYPE::from(CKM_DES3_CMAC),
            MechanismType::Des3EcbEncryptData => CK_MECHANISM_TYPE::from(CKM_DES3_ECB_ENCRYPT_DATA),
            MechanismType::Des3CbcEncryptData => CK_MECHANISM_TYPE::from(CKM_DES3_CBC_ENCRYPT_DATA),
            MechanismType::DesCbc => CK_MECHANISM_TYPE::from(CKM_DES_CBC),
            MechanismType::DesCbcEncryptData => CK_MECHANISM_TYPE::from(CKM_DES_CBC_ENCRYPT_DATA),
            MechanismType::DesCbcPad => CK_MECHANISM_TYPE::from(CKM_DES_CBC_PAD),
            MechanismType::DesCfb8 => CK_MECHANISM_TYPE::from(CKM_DES_CFB8),
            MechanismType::DesCfb64 => CK_MECHANISM_TYPE::from(CKM_DES_CFB64),
            MechanismType::DesEcb => CK_MECHANISM_TYPE::from(CKM_DES_ECB),
            MechanismType::DesEcbEncryptData => CK_MECHANISM_TYPE::from(CKM_DES_ECB_ENCRYPT_DATA),
            MechanismType::DesKeyGen => CK_MECHANISM_TYPE::from(CKM_DES_KEY_GEN),
            MechanismType::DesMac => CK_MECHANISM_TYPE::from(CKM_DES_MAC),
            MechanismType::DesMacGeneral => CK_MECHANISM_TYPE::from(CKM_DES_MAC_GENERAL),
            MechanismType::DesOfb8 => CK_MECHANISM_TYPE::from(CKM_DES_OFB8),
            MechanismType::DesOfb64 => CK_MECHANISM_TYPE::from(CKM_DES_OFB64),
            MechanismType::DhPkcsDerive => CK_MECHANISM_TYPE::from(CKM_DH_PKCS_DERIVE),
            MechanismType::DhPkcsKeyPairGen => CK_MECHANISM_TYPE::from(CKM_DH_PKCS_KEY_PAIR_GEN),
            MechanismType::DhPkcsParameterGen => CK_MECHANISM_TYPE::from(CKM_DH_PKCS_PARAMETER_GEN),
            MechanismType::Dsa => CK_MECHANISM_TYPE::from(CKM_DSA),
            MechanismType::DsaKeyPairGen => CK_MECHANISM_TYPE::from(CKM_DSA_KEY_PAIR_GEN),
            MechanismType::DsaParameterGen => CK_MECHANISM_TYPE::from(CKM_DSA_PARAMETER_GEN),
            MechanismType::DsaProbablisticParameterGen => {
                CK_MECHANISM_TYPE::from(CKM_DSA_PROBABLISTIC_PARAMETER_GEN)
            }
            MechanismType::DsaSha1 => CK_MECHANISM_TYPE::from(CKM_DSA_SHA1),
            MechanismType::DsaSha224 => CK_MECHANISM_TYPE::from(CKM_DSA_SHA224),
            MechanismType::DsaSha256 => CK_MECHANISM_TYPE::from(CKM_DSA_SHA256),
            MechanismType::DsaSha384 => CK_MECHANISM_TYPE::from(CKM_DSA_SHA384),
            MechanismType::DsaSha512 => CK_MECHANISM_TYPE::from(CKM_DSA_SHA512),
            MechanismType::DsaShaweTaylorParameterGen => {
                CK_MECHANISM_TYPE::from(CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN)
            }
            MechanismType::Ecdh1Derive => CK_MECHANISM_TYPE::from(CKM_ECDH1_DERIVE),
            MechanismType::Ecdh1CofactorDerive => {
                CK_MECHANISM_TYPE::from(CKM_ECDH1_COFACTOR_DERIVE)
            }
            MechanismType::EcdhAesKeyWrap => CK_MECHANISM_TYPE::from(CKM_ECDH_AES_KEY_WRAP),
            MechanismType::Ecdsa => CK_MECHANISM_TYPE::from(CKM_ECDSA),
            MechanismType::EcdsaKeyPairGen => CK_MECHANISM_TYPE::from(CKM_ECDSA_KEY_PAIR_GEN),
            MechanismType::EcdsaSha1 => CK_MECHANISM_TYPE::from(CKM_ECDSA_SHA1),
            MechanismType::EcdsaSha224 => CK_MECHANISM_TYPE::from(CKM_ECDSA_SHA224),
            MechanismType::EcdsaSha256 => CK_MECHANISM_TYPE::from(CKM_ECDSA_SHA256),
            MechanismType::EcdsaSha384 => CK_MECHANISM_TYPE::from(CKM_ECDSA_SHA384),
            MechanismType::EcdsaSha512 => CK_MECHANISM_TYPE::from(CKM_ECDSA_SHA512),
            MechanismType::EcmqvDerive => CK_MECHANISM_TYPE::from(CKM_ECMQV_DERIVE),
            MechanismType::EcKeyPairGen => CK_MECHANISM_TYPE::from(CKM_EC_KEY_PAIR_GEN),
            MechanismType::ExtractKeyFromKey => CK_MECHANISM_TYPE::from(CKM_EXTRACT_KEY_FROM_KEY),
            MechanismType::Fasthash => CK_MECHANISM_TYPE::from(CKM_FASTHASH),
            MechanismType::FortezzaTimestamp => CK_MECHANISM_TYPE::from(CKM_FORTEZZA_TIMESTAMP),
            MechanismType::GenericSecretKeyGen => {
                CK_MECHANISM_TYPE::from(CKM_GENERIC_SECRET_KEY_GEN)
            }
            MechanismType::Gost28147KeyGen => CK_MECHANISM_TYPE::from(CKM_GOST28147_KEY_GEN),
            MechanismType::Gost28147Ecb => CK_MECHANISM_TYPE::from(CKM_GOST28147_ECB),
            MechanismType::Gost28147 => CK_MECHANISM_TYPE::from(CKM_GOST28147),
            MechanismType::Gost28147Mac => CK_MECHANISM_TYPE::from(CKM_GOST28147_MAC),
            MechanismType::Gost28147KeyWrap => CK_MECHANISM_TYPE::from(CKM_GOST28147_KEY_WRAP),
            MechanismType::Gostr3410KeyPairGen => {
                CK_MECHANISM_TYPE::from(CKM_GOSTR3410_KEY_PAIR_GEN)
            }
            MechanismType::Gostr3410 => CK_MECHANISM_TYPE::from(CKM_GOSTR3410),
            MechanismType::Gostr3410KeyWrap => CK_MECHANISM_TYPE::from(CKM_GOSTR3410_KEY_WRAP),
            MechanismType::Gostr3410Derive => CK_MECHANISM_TYPE::from(CKM_GOSTR3410_DERIVE),
            MechanismType::Gostr3411 => CK_MECHANISM_TYPE::from(CKM_GOSTR3411),
            MechanismType::Gostr3411Hmac => CK_MECHANISM_TYPE::from(CKM_GOSTR3411_HMAC),
            MechanismType::Gostr3410WithGostr3411 => {
                CK_MECHANISM_TYPE::from(CKM_GOSTR3410_WITH_GOSTR3411)
            }
            MechanismType::Hotp => CK_MECHANISM_TYPE::from(CKM_HOTP),
            MechanismType::HotpKeyGen => CK_MECHANISM_TYPE::from(CKM_HOTP_KEY_GEN),
            MechanismType::IdeaCbc => CK_MECHANISM_TYPE::from(CKM_IDEA_CBC),
            MechanismType::IdeaCbcPad => CK_MECHANISM_TYPE::from(CKM_IDEA_CBC_PAD),
            MechanismType::IdeaEcb => CK_MECHANISM_TYPE::from(CKM_IDEA_ECB),
            MechanismType::IdeaKeyGen => CK_MECHANISM_TYPE::from(CKM_IDEA_KEY_GEN),
            MechanismType::IdeaMac => CK_MECHANISM_TYPE::from(CKM_IDEA_MAC),
            MechanismType::IdeaMacGeneral => CK_MECHANISM_TYPE::from(CKM_IDEA_MAC_GENERAL),
            MechanismType::JuniperCbc128 => CK_MECHANISM_TYPE::from(CKM_JUNIPER_CBC128),
            MechanismType::JuniperCounter => CK_MECHANISM_TYPE::from(CKM_JUNIPER_COUNTER),
            MechanismType::JuniperEcb128 => CK_MECHANISM_TYPE::from(CKM_JUNIPER_ECB128),
            MechanismType::JuniperKeyGen => CK_MECHANISM_TYPE::from(CKM_JUNIPER_KEY_GEN),
            MechanismType::JuniperShuffle => CK_MECHANISM_TYPE::from(CKM_JUNIPER_SHUFFLE),
            MechanismType::JuniperWrap => CK_MECHANISM_TYPE::from(CKM_JUNIPER_WRAP),
            MechanismType::KeaDerive => CK_MECHANISM_TYPE::from(CKM_KEA_DERIVE),
            MechanismType::KeaKeyDerive => CK_MECHANISM_TYPE::from(CKM_KEA_KEY_DERIVE),
            MechanismType::KeaKeyPairGen => CK_MECHANISM_TYPE::from(CKM_KEA_KEY_PAIR_GEN),
            MechanismType::KeyWrapLynks => CK_MECHANISM_TYPE::from(CKM_KEY_WRAP_LYNKS),
            MechanismType::KeyWrapSetOaep => CK_MECHANISM_TYPE::from(CKM_KEY_WRAP_SET_OAEP),
            MechanismType::KipDerive => CK_MECHANISM_TYPE::from(CKM_KIP_DERIVE),
            MechanismType::KipMac => CK_MECHANISM_TYPE::from(CKM_KIP_MAC),
            MechanismType::KipWrap => CK_MECHANISM_TYPE::from(CKM_KIP_WRAP),
            MechanismType::Md2RsaPkcs => CK_MECHANISM_TYPE::from(CKM_MD2_RSA_PKCS),
            MechanismType::Md2 => CK_MECHANISM_TYPE::from(CKM_MD2),
            MechanismType::Md2Hmac => CK_MECHANISM_TYPE::from(CKM_MD2_HMAC),
            MechanismType::Md2HmacGeneral => CK_MECHANISM_TYPE::from(CKM_MD2_HMAC_GENERAL),
            MechanismType::Md2KeyDerivation => CK_MECHANISM_TYPE::from(CKM_MD2_KEY_DERIVATION),
            MechanismType::Md5RsaPkcs => CK_MECHANISM_TYPE::from(CKM_MD5_RSA_PKCS),
            MechanismType::Md5 => CK_MECHANISM_TYPE::from(CKM_MD5),
            MechanismType::Md5Hmac => CK_MECHANISM_TYPE::from(CKM_MD5_HMAC),
            MechanismType::Md5HmacGeneral => CK_MECHANISM_TYPE::from(CKM_MD5_HMAC_GENERAL),
            MechanismType::Md5KeyDerivation => CK_MECHANISM_TYPE::from(CKM_MD5_KEY_DERIVATION),
            MechanismType::PbaSha1WithSha1Hmac => {
                CK_MECHANISM_TYPE::from(CKM_PBA_SHA1_WITH_SHA1_HMAC)
            }
            MechanismType::PbeMd2DesCbc => CK_MECHANISM_TYPE::from(CKM_PBE_MD2_DES_CBC),
            MechanismType::PbeMd5DesCbc => CK_MECHANISM_TYPE::from(CKM_PBE_MD5_DES_CBC),
            MechanismType::PbeMd5CastCbc => CK_MECHANISM_TYPE::from(CKM_PBE_MD5_CAST_CBC),
            MechanismType::PbeMd5Cast3Cbc => CK_MECHANISM_TYPE::from(CKM_PBE_MD5_CAST3_CBC),
            MechanismType::PbeMd5Cast5Cbc => CK_MECHANISM_TYPE::from(CKM_PBE_MD5_CAST5_CBC),
            MechanismType::PbeMd5Cast128Cbc => CK_MECHANISM_TYPE::from(CKM_PBE_MD5_CAST128_CBC),
            MechanismType::PbeSha1Cast5Cbc => CK_MECHANISM_TYPE::from(CKM_PBE_SHA1_CAST5_CBC),
            MechanismType::PbeSha1Cast128Cbc => CK_MECHANISM_TYPE::from(CKM_PBE_SHA1_CAST128_CBC),
            MechanismType::PbeSha1Des2EdeCbc => CK_MECHANISM_TYPE::from(CKM_PBE_SHA1_DES2_EDE_CBC),
            MechanismType::PbeSha1Des3EdeCbc => CK_MECHANISM_TYPE::from(CKM_PBE_SHA1_DES3_EDE_CBC),
            MechanismType::PbeSha1Rc2_40Cbc => CK_MECHANISM_TYPE::from(CKM_PBE_SHA1_RC2_40_CBC),
            MechanismType::PbeSha1Rc2_128Cbc => CK_MECHANISM_TYPE::from(CKM_PBE_SHA1_RC2_128_CBC),
            MechanismType::PbeSha1Rc4_40 => CK_MECHANISM_TYPE::from(CKM_PBE_SHA1_RC4_40),
            MechanismType::PbeSha1Rc4_128 => CK_MECHANISM_TYPE::from(CKM_PBE_SHA1_RC4_128),
            MechanismType::Pkcs5Pbkd2 => CK_MECHANISM_TYPE::from(CKM_PKCS5_PBKD2),
            MechanismType::Rc2KeyGen => CK_MECHANISM_TYPE::from(CKM_RC2_KEY_GEN),
            MechanismType::Rc2Ecb => CK_MECHANISM_TYPE::from(CKM_RC2_ECB),
            MechanismType::Rc2Cbc => CK_MECHANISM_TYPE::from(CKM_RC2_CBC),
            MechanismType::Rc2Mac => CK_MECHANISM_TYPE::from(CKM_RC2_MAC),
            MechanismType::Rc2MacGeneral => CK_MECHANISM_TYPE::from(CKM_RC2_MAC_GENERAL),
            MechanismType::Rc2CbcPad => CK_MECHANISM_TYPE::from(CKM_RC2_CBC_PAD),
            MechanismType::Rc4KeyGen => CK_MECHANISM_TYPE::from(CKM_RC4_KEY_GEN),
            MechanismType::Rc4 => CK_MECHANISM_TYPE::from(CKM_RC4),
            MechanismType::Rc5KeyGen => CK_MECHANISM_TYPE::from(CKM_RC5_KEY_GEN),
            MechanismType::Rc5Ecb => CK_MECHANISM_TYPE::from(CKM_RC5_ECB),
            MechanismType::Rc5Cbc => CK_MECHANISM_TYPE::from(CKM_RC5_CBC),
            MechanismType::Rc5Mac => CK_MECHANISM_TYPE::from(CKM_RC5_MAC),
            MechanismType::Rc5MacGeneral => CK_MECHANISM_TYPE::from(CKM_RC5_MAC_GENERAL),
            MechanismType::Rrc5CbcPad => CK_MECHANISM_TYPE::from(CKM_RC5_CBC_PAD),
            MechanismType::Ripemd128RsaPkcs => CK_MECHANISM_TYPE::from(CKM_RIPEMD128_RSA_PKCS),
            MechanismType::Ripemd128 => CK_MECHANISM_TYPE::from(CKM_RIPEMD128),
            MechanismType::Ripemd128Hmac => CK_MECHANISM_TYPE::from(CKM_RIPEMD128_HMAC),
            MechanismType::Ripemd128HmacGeneral => {
                CK_MECHANISM_TYPE::from(CKM_RIPEMD128_HMAC_GENERAL)
            }
            MechanismType::Ripemd160RsaPkcs => CK_MECHANISM_TYPE::from(CKM_RIPEMD160_RSA_PKCS),
            MechanismType::Ripemd160 => CK_MECHANISM_TYPE::from(CKM_RIPEMD160),
            MechanismType::Ripemd160Hmac => CK_MECHANISM_TYPE::from(CKM_RIPEMD160_HMAC),
            MechanismType::Ripemd160HmacGeneral => {
                CK_MECHANISM_TYPE::from(CKM_RIPEMD160_HMAC_GENERAL)
            }
            MechanismType::Rsa9796 => CK_MECHANISM_TYPE::from(CKM_RSA_9796),
            MechanismType::RsaAesKeyWrap => CK_MECHANISM_TYPE::from(CKM_RSA_AES_KEY_WRAP),
            MechanismType::RsaPkcs => CK_MECHANISM_TYPE::from(CKM_RSA_PKCS),
            MechanismType::RsaPkcsKeyPairGen => CK_MECHANISM_TYPE::from(CKM_RSA_PKCS_KEY_PAIR_GEN),
            MechanismType::RsaPkcsOaep => CK_MECHANISM_TYPE::from(CKM_RSA_PKCS_OAEP),
            MechanismType::RsaPkcsOaepTpm11 => CK_MECHANISM_TYPE::from(CKM_RSA_PKCS_OAEP_TPM_1_1),
            MechanismType::RsaPkcsPss => CK_MECHANISM_TYPE::from(CKM_RSA_PKCS_PSS),
            MechanismType::RsaPkcsTpm11 => CK_MECHANISM_TYPE::from(CKM_RSA_PKCS_TPM_1_1),
            MechanismType::RsaX9_31KeyPairGen => {
                CK_MECHANISM_TYPE::from(CKM_RSA_X9_31_KEY_PAIR_GEN)
            }
            MechanismType::RsaX9_31 => CK_MECHANISM_TYPE::from(CKM_RSA_X9_31),
            MechanismType::RsaX509 => CK_MECHANISM_TYPE::from(CKM_RSA_X_509),
            MechanismType::Securid => CK_MECHANISM_TYPE::from(CKM_SECURID),
            MechanismType::SecuridKeyGen => CK_MECHANISM_TYPE::from(CKM_SECURID_KEY_GEN),
            MechanismType::SeedCbc => CK_MECHANISM_TYPE::from(CKM_SEED_CBC),
            MechanismType::SeedCbcEncryptData => CK_MECHANISM_TYPE::from(CKM_SEED_CBC_ENCRYPT_DATA),
            MechanismType::SeedCbcPad => CK_MECHANISM_TYPE::from(CKM_SEED_CBC_PAD),
            MechanismType::SeedEcb => CK_MECHANISM_TYPE::from(CKM_SEED_ECB),
            MechanismType::SeedEcbEncryptData => CK_MECHANISM_TYPE::from(CKM_SEED_ECB_ENCRYPT_DATA),
            MechanismType::SeedKeyGen => CK_MECHANISM_TYPE::from(CKM_SEED_KEY_GEN),
            MechanismType::SeedMac => CK_MECHANISM_TYPE::from(CKM_SEED_MAC),
            MechanismType::SeedMacGeneral => CK_MECHANISM_TYPE::from(CKM_SEED_MAC_GENERAL),
            MechanismType::Sha1RsaPkcs => CK_MECHANISM_TYPE::from(CKM_SHA1_RSA_PKCS),
            MechanismType::Sha1RsaPkcsPss => CK_MECHANISM_TYPE::from(CKM_SHA1_RSA_PKCS_PSS),
            MechanismType::Sha1KeyDerivation => CK_MECHANISM_TYPE::from(CKM_SHA1_KEY_DERIVATION),
            MechanismType::Sha224RsaPkcs => CK_MECHANISM_TYPE::from(CKM_SHA224_RSA_PKCS),
            MechanismType::Sha224RsaPkcsPss => CK_MECHANISM_TYPE::from(CKM_SHA224_RSA_PKCS_PSS),
            MechanismType::Sha224 => CK_MECHANISM_TYPE::from(CKM_SHA224),
            MechanismType::Sha224Hmac => CK_MECHANISM_TYPE::from(CKM_SHA224_HMAC),
            MechanismType::Sha224HmacGeneral => CK_MECHANISM_TYPE::from(CKM_SHA224_HMAC_GENERAL),
            MechanismType::Sha224KeyDerivation => {
                CK_MECHANISM_TYPE::from(CKM_SHA224_KEY_DERIVATION)
            }
            MechanismType::Sha256RsaPkcs => CK_MECHANISM_TYPE::from(CKM_SHA256_RSA_PKCS),
            MechanismType::Sha256RsaPkcsPss => CK_MECHANISM_TYPE::from(CKM_SHA256_RSA_PKCS_PSS),
            MechanismType::Sha256 => CK_MECHANISM_TYPE::from(CKM_SHA256),
            MechanismType::Sha256Hmac => CK_MECHANISM_TYPE::from(CKM_SHA256_HMAC),
            MechanismType::Sha256HmacGeneral => CK_MECHANISM_TYPE::from(CKM_SHA256_HMAC_GENERAL),
            MechanismType::Sha256KeyDerivation => {
                CK_MECHANISM_TYPE::from(CKM_SHA256_KEY_DERIVATION)
            }
            MechanismType::Sha384RsaPkcs => CK_MECHANISM_TYPE::from(CKM_SHA384_RSA_PKCS),
            MechanismType::Sha384RsaPkcsPss => CK_MECHANISM_TYPE::from(CKM_SHA384_RSA_PKCS_PSS),
            MechanismType::Sha384 => CK_MECHANISM_TYPE::from(CKM_SHA384),
            MechanismType::Sha384Hmac => CK_MECHANISM_TYPE::from(CKM_SHA384_HMAC),
            MechanismType::Sha384HmacGeneral => CK_MECHANISM_TYPE::from(CKM_SHA384_HMAC_GENERAL),
            MechanismType::Sha384KeyDerivation => {
                CK_MECHANISM_TYPE::from(CKM_SHA384_KEY_DERIVATION)
            }
            MechanismType::Sha512RsaPkcs => CK_MECHANISM_TYPE::from(CKM_SHA512_RSA_PKCS),
            MechanismType::Sha512RsaPkcsPss => CK_MECHANISM_TYPE::from(CKM_SHA512_RSA_PKCS_PSS),
            MechanismType::Sha512T => CK_MECHANISM_TYPE::from(CKM_SHA512_T),
            MechanismType::Sha512THmac => CK_MECHANISM_TYPE::from(CKM_SHA512_T_HMAC),
            MechanismType::Sha512THmacGeneral => CK_MECHANISM_TYPE::from(CKM_SHA512_T_HMAC_GENERAL),
            MechanismType::Sha512TKeyDerivation => {
                CK_MECHANISM_TYPE::from(CKM_SHA512_T_KEY_DERIVATION)
            }
            MechanismType::Sha512 => CK_MECHANISM_TYPE::from(CKM_SHA512),
            MechanismType::Sha512Hmac => CK_MECHANISM_TYPE::from(CKM_SHA512_HMAC),
            MechanismType::Sha512HmacGeneral => CK_MECHANISM_TYPE::from(CKM_SHA512_HMAC_GENERAL),
            MechanismType::Sha512KeyDerivation => {
                CK_MECHANISM_TYPE::from(CKM_SHA512_KEY_DERIVATION)
            }
            MechanismType::Sha1RsaX9_31 => CK_MECHANISM_TYPE::from(CKM_SHA1_RSA_X9_31),
            MechanismType::Sha512_224 => CK_MECHANISM_TYPE::from(CKM_SHA512_224),
            MechanismType::Sha512_224Hmac => CK_MECHANISM_TYPE::from(CKM_SHA512_224_HMAC),
            MechanismType::Sha512_224HmacGeneral => {
                CK_MECHANISM_TYPE::from(CKM_SHA512_224_HMAC_GENERAL)
            }
            MechanismType::Sha512_224KeyDerivation => {
                CK_MECHANISM_TYPE::from(CKM_SHA512_224_KEY_DERIVATION)
            }
            MechanismType::Sha512_256 => CK_MECHANISM_TYPE::from(CKM_SHA512_256),
            MechanismType::Sha512_256Hmac => CK_MECHANISM_TYPE::from(CKM_SHA512_256_HMAC),
            MechanismType::Sha512_256HmacGeneral => {
                CK_MECHANISM_TYPE::from(CKM_SHA512_256_HMAC_GENERAL)
            }
            MechanismType::Sha512_256KeyDerivation => {
                CK_MECHANISM_TYPE::from(CKM_SHA512_256_KEY_DERIVATION)
            }
            MechanismType::Sha1 => CK_MECHANISM_TYPE::from(CKM_SHA_1),
            MechanismType::Sha1Hmac => CK_MECHANISM_TYPE::from(CKM_SHA_1_HMAC),
            MechanismType::Sha1HmacGeneral => CK_MECHANISM_TYPE::from(CKM_SHA_1_HMAC_GENERAL),
            MechanismType::SkipjackCbc64 => CK_MECHANISM_TYPE::from(CKM_SKIPJACK_CBC64),
            MechanismType::SkipjackCfb8 => CK_MECHANISM_TYPE::from(CKM_SKIPJACK_CFB8),
            MechanismType::SkipjackCfb16 => CK_MECHANISM_TYPE::from(CKM_SKIPJACK_CFB16),
            MechanismType::SkipjackCfb32 => CK_MECHANISM_TYPE::from(CKM_SKIPJACK_CFB32),
            MechanismType::SkipjackCfb64 => CK_MECHANISM_TYPE::from(CKM_SKIPJACK_CFB64),
            MechanismType::SkipjackEcb64 => CK_MECHANISM_TYPE::from(CKM_SKIPJACK_ECB64),
            MechanismType::SkipjackKeyGen => CK_MECHANISM_TYPE::from(CKM_SKIPJACK_KEY_GEN),
            MechanismType::SkipjackOfb64 => CK_MECHANISM_TYPE::from(CKM_SKIPJACK_OFB64),
            MechanismType::SkipjackPrivateWrap => {
                CK_MECHANISM_TYPE::from(CKM_SKIPJACK_PRIVATE_WRAP)
            }
            MechanismType::SkipjackRelayx => CK_MECHANISM_TYPE::from(CKM_SKIPJACK_RELAYX),
            MechanismType::SkipjackWrap => CK_MECHANISM_TYPE::from(CKM_SKIPJACK_WRAP),
            MechanismType::Ssl3PreMasterKeyGen => {
                CK_MECHANISM_TYPE::from(CKM_SSL3_PRE_MASTER_KEY_GEN)
            }
            MechanismType::Ssl3MasterKeyDerive => {
                CK_MECHANISM_TYPE::from(CKM_SSL3_MASTER_KEY_DERIVE)
            }
            MechanismType::Ssl3KeyAndMacDerive => {
                CK_MECHANISM_TYPE::from(CKM_SSL3_KEY_AND_MAC_DERIVE)
            }
            MechanismType::Ssl3MasterKeyDeriveDh => {
                CK_MECHANISM_TYPE::from(CKM_SSL3_MASTER_KEY_DERIVE_DH)
            }
            MechanismType::Ssl3Md5Mac => CK_MECHANISM_TYPE::from(CKM_SSL3_MD5_MAC),
            MechanismType::Ssl3Sha1Mac => CK_MECHANISM_TYPE::from(CKM_SSL3_SHA1_MAC),
            MechanismType::Tls10MacServer => CK_MECHANISM_TYPE::from(CKM_TLS10_MAC_SERVER),
            MechanismType::Tls10MacClient => CK_MECHANISM_TYPE::from(CKM_TLS10_MAC_CLIENT),
            MechanismType::Tls12Mac => CK_MECHANISM_TYPE::from(CKM_TLS12_MAC),
            MechanismType::Tls12Kdf => CK_MECHANISM_TYPE::from(CKM_TLS12_KDF),
            MechanismType::Tls12MasterKeyDerive => {
                CK_MECHANISM_TYPE::from(CKM_TLS12_MASTER_KEY_DERIVE)
            }
            MechanismType::Tls12KeyAndMacDerive => {
                CK_MECHANISM_TYPE::from(CKM_TLS12_KEY_AND_MAC_DERIVE)
            }
            MechanismType::Tls12MasterKeyDeriveDh => {
                CK_MECHANISM_TYPE::from(CKM_TLS12_MASTER_KEY_DERIVE_DH)
            }
            MechanismType::Tls12KeySafeDerive => CK_MECHANISM_TYPE::from(CKM_TLS12_KEY_SAFE_DERIVE),
            MechanismType::TlsKdf => CK_MECHANISM_TYPE::from(CKM_TLS_KDF),
            MechanismType::TlsKeyAndMacDerive => {
                CK_MECHANISM_TYPE::from(CKM_TLS_KEY_AND_MAC_DERIVE)
            }
            MechanismType::TlsMac => CK_MECHANISM_TYPE::from(CKM_TLS_MAC),
            MechanismType::TlsMasterKeyDerive => CK_MECHANISM_TYPE::from(CKM_TLS_MASTER_KEY_DERIVE),
            MechanismType::TlsMasterKeyDeriveDh => {
                CK_MECHANISM_TYPE::from(CKM_TLS_MASTER_KEY_DERIVE_DH)
            }
            MechanismType::TlsPreMasterKeyGen => {
                CK_MECHANISM_TYPE::from(CKM_TLS_PRE_MASTER_KEY_GEN)
            }
            MechanismType::TlsPrf => CK_MECHANISM_TYPE::from(CKM_TLS_PRF),
            MechanismType::TwofishCbc => CK_MECHANISM_TYPE::from(CKM_TWOFISH_CBC),
            MechanismType::TwofishCbcPad => CK_MECHANISM_TYPE::from(CKM_TWOFISH_CBC_PAD),
            MechanismType::TwofishKeyGen => CK_MECHANISM_TYPE::from(CKM_TWOFISH_KEY_GEN),
            MechanismType::VendorDefined => CK_MECHANISM_TYPE::from(CKM_VENDOR_DEFINED),
            MechanismType::WtlsClientKeyAndMacDerive => {
                CK_MECHANISM_TYPE::from(CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE)
            }
            MechanismType::WtlsMasterKeyDerive => {
                CK_MECHANISM_TYPE::from(CKM_WTLS_MASTER_KEY_DERIVE)
            }
            MechanismType::WtlsMasterKeyDeriveDhEcc => {
                CK_MECHANISM_TYPE::from(CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC)
            }
            MechanismType::WtlsPreMasterKeyGen => {
                CK_MECHANISM_TYPE::from(CKM_WTLS_PRE_MASTER_KEY_GEN)
            }
            MechanismType::WtlsPrf => CK_MECHANISM_TYPE::from(CKM_WTLS_PRF),
            MechanismType::WtlsServerKeyAndMacDerive => {
                CK_MECHANISM_TYPE::from(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE)
            }
            MechanismType::X9_42DhKeyPairGen => CK_MECHANISM_TYPE::from(CKM_X9_42_DH_KEY_PAIR_GEN),
            MechanismType::X9_42DhDerive => CK_MECHANISM_TYPE::from(CKM_X9_42_DH_DERIVE),
            MechanismType::X9_42DhHybridDerive => {
                CK_MECHANISM_TYPE::from(CKM_X9_42_DH_HYBRID_DERIVE)
            }
            MechanismType::X9_42MqvDerive => CK_MECHANISM_TYPE::from(CKM_X9_42_MQV_DERIVE),
            MechanismType::X9_42DhParameterGen => {
                CK_MECHANISM_TYPE::from(CKM_X9_42_DH_PARAMETER_GEN)
            }
            MechanismType::XorBaseAndData => CK_MECHANISM_TYPE::from(CKM_XOR_BASE_AND_DATA),
        }
    }
}

impl From<CK_MECHANISM_TYPE> for MechanismType {
    fn from(mechanism_type: CK_MECHANISM_TYPE) -> MechanismType {
        match mechanism_type as u32 {
            CKM_ACTI => MechanismType::Acti,
            CKM_ACTI_KEY_GEN => MechanismType::ActiKeyGen,
            CKM_AES_CBC => MechanismType::AesCbc,
            CKM_AES_CBC_ENCRYPT_DATA => MechanismType::AesCbcEncryptData,
            CKM_AES_CBC_PAD => MechanismType::AesCbcPad,
            CKM_AES_CCM => MechanismType::AesCcm,
            CKM_AES_CFB1 => MechanismType::AesCfb1,
            CKM_AES_CFB8 => MechanismType::AesCfb8,
            CKM_AES_CFB64 => MechanismType::AesCfb64,
            CKM_AES_CFB128 => MechanismType::AesCfb128,
            CKM_AES_CMAC => MechanismType::AesCmac,
            CKM_AES_CMAC_GENERAL => MechanismType::AesCmacGeneral,
            CKM_AES_CTR => MechanismType::AesCtr,
            CKM_AES_CTS => MechanismType::AesCts,
            CKM_AES_ECB => MechanismType::AesEcb,
            CKM_AES_ECB_ENCRYPT_DATA => MechanismType::AesEcbEncryptData,
            CKM_AES_GCM => MechanismType::AesGcm,
            CKM_AES_GMAC => MechanismType::AesGmac,
            CKM_AES_KEY_GEN => MechanismType::AesKeyGen,
            CKM_AES_KEY_WRAP => MechanismType::AesKeyWrap,
            CKM_AES_KEY_WRAP_PAD => MechanismType::AesKeyWrapPad,
            CKM_AES_MAC => MechanismType::AesMac,
            CKM_AES_MAC_GENERAL => MechanismType::AesMacGeneral,
            CKM_AES_OFB => MechanismType::AesOfb,
            CKM_AES_XCBC_MAC => MechanismType::AesXcbcMac,
            CKM_AES_XCBC_MAC_96 => MechanismType::AesXcbcMac96,
            CKM_ARIA_CBC => MechanismType::AriaCbc,
            CKM_ARIA_CBC_ENCRYPT_DATA => MechanismType::AriaCbcEncryptData,
            CKM_ARIA_CBC_PAD => MechanismType::AriaCbcPad,
            CKM_ARIA_ECB => MechanismType::AriaEcb,
            CKM_ARIA_ECB_ENCRYPT_DATA => MechanismType::AriaEcbEncryptData,
            CKM_ARIA_KEY_GEN => MechanismType::AriaKeyGen,
            CKM_ARIA_MAC => MechanismType::AriaMac,
            CKM_ARIA_MAC_GENERAL => MechanismType::AriaMacGeneral,
            CKM_BATON_CBC128 => MechanismType::BatonCbc128,
            CKM_BATON_COUNTER => MechanismType::BatonCounter,
            CKM_BATON_ECB96 => MechanismType::BatonEcb96,
            CKM_BATON_ECB128 => MechanismType::BatonEcb128,
            CKM_BATON_KEY_GEN => MechanismType::BatonKeyGen,
            CKM_BATON_SHUFFLE => MechanismType::BatonShuffle,
            CKM_BATON_WRAP => MechanismType::BatonWrap,
            CKM_BLOWFISH_CBC => MechanismType::BlowfishCbc,
            CKM_BLOWFISH_CBC_PAD => MechanismType::BlowfishCbcPad,
            CKM_BLOWFISH_KEY_GEN => MechanismType::BlowfishKeyGen,
            CKM_CAMELLIA_CBC => MechanismType::CamelliaCbc,
            CKM_CAMELLIA_CBC_ENCRYPT_DATA => MechanismType::CamelliaCbcEncryptData,
            CKM_CAMELLIA_CBC_PAD => MechanismType::CamelliaCbcPad,
            CKM_CAMELLIA_CTR => MechanismType::CamelliaCtr,
            CKM_CAMELLIA_ECB => MechanismType::CamelliaEcb,
            CKM_CAMELLIA_ECB_ENCRYPT_DATA => MechanismType::CamelliaEcbEncryptData,
            CKM_CAMELLIA_KEY_GEN => MechanismType::CamelliaKeyGen,
            CKM_CAMELLIA_MAC => MechanismType::CamelliaMac,
            CKM_CAMELLIA_MAC_GENERAL => MechanismType::CamelliaMacGeneral,
            CKM_CAST3_KEY_GEN => MechanismType::Cast3KeyGen,
            CKM_CAST3_ECB => MechanismType::Cast3Ecb,
            CKM_CAST3_CBC => MechanismType::Cast3Cbc,
            CKM_CAST3_MAC => MechanismType::Cast3Mac,
            CKM_CAST3_MAC_GENERAL => MechanismType::Cast3MacGeneral,
            CKM_CAST3_CBC_PAD => MechanismType::Cast3CbcPad,
            CKM_CAST5_KEY_GEN => MechanismType::Cast5KeyGen,
            CKM_CAST5_ECB => MechanismType::Cast5Ecb,
            CKM_CAST5_CBC => MechanismType::Cast5Cbc,
            CKM_CAST5_MAC => MechanismType::Cast5Mac,
            CKM_CAST5_MAC_GENERAL => MechanismType::Cast5MacGeneral,
            CKM_CAST5_CBC_PAD => MechanismType::Cast5CbcPad,
            CKM_CAST_CBC => MechanismType::CastCbc,
            CKM_CAST_CBC_PAD => MechanismType::CastCbcPad,
            CKM_CAST_ECB => MechanismType::CastEcb,
            CKM_CAST_KEY_GEN => MechanismType::CastKeyGen,
            CKM_CAST_MAC => MechanismType::CastMac,
            CKM_CAST_MAC_GENERAL => MechanismType::CastMacGeneral,
            CKM_CDMF_CBC => MechanismType::CdmfCbc,
            CKM_CDMF_CBC_PAD => MechanismType::CdmfCbcPad,
            CKM_CDMF_ECB => MechanismType::CdmfEcb,
            CKM_CDMF_KEY_GEN => MechanismType::CdmfKeyGen,
            CKM_CDMF_MAC => MechanismType::CdmfMac,
            CKM_CDMF_MAC_GENERAL => MechanismType::CdmfMacGeneral,
            CKM_CMS_SIG => MechanismType::CmsSig,
            CKM_CONCATENATE_BASE_AND_DATA => MechanismType::ConcatenateBaseAndData,
            CKM_CONCATENATE_BASE_AND_KEY => MechanismType::ConcatenateBaseAndKey,
            CKM_CONCATENATE_DATA_AND_BASE => MechanismType::ConcatenateDataAndBase,
            CKM_DES2_KEY_GEN => MechanismType::Des2KeyGen,
            CKM_DES3_KEY_GEN => MechanismType::Des3KeyGen,
            CKM_DES3_ECB => MechanismType::Des3Ecb,
            CKM_DES3_CBC => MechanismType::Des3Cbc,
            CKM_DES3_MAC => MechanismType::Des3Mac,
            CKM_DES3_MAC_GENERAL => MechanismType::Des3MacGeneral,
            CKM_DES3_CBC_PAD => MechanismType::Des3CbcPad,
            CKM_DES3_CMAC_GENERAL => MechanismType::Des3CmacGeneral,
            CKM_DES3_CMAC => MechanismType::Des3Cmac,
            CKM_DES3_ECB_ENCRYPT_DATA => MechanismType::Des3EcbEncryptData,
            CKM_DES3_CBC_ENCRYPT_DATA => MechanismType::Des3CbcEncryptData,
            CKM_DES_CBC => MechanismType::DesCbc,
            CKM_DES_CBC_ENCRYPT_DATA => MechanismType::DesCbcEncryptData,
            CKM_DES_CBC_PAD => MechanismType::DesCbcPad,
            CKM_DES_CFB8 => MechanismType::DesCfb8,
            CKM_DES_CFB64 => MechanismType::DesCfb64,
            CKM_DES_ECB => MechanismType::DesEcb,
            CKM_DES_ECB_ENCRYPT_DATA => MechanismType::DesEcbEncryptData,
            CKM_DES_KEY_GEN => MechanismType::DesKeyGen,
            CKM_DES_MAC => MechanismType::DesMac,
            CKM_DES_MAC_GENERAL => MechanismType::DesMacGeneral,
            CKM_DES_OFB8 => MechanismType::DesOfb8,
            CKM_DES_OFB64 => MechanismType::DesOfb64,
            CKM_DH_PKCS_DERIVE => MechanismType::DhPkcsDerive,
            CKM_DH_PKCS_KEY_PAIR_GEN => MechanismType::DhPkcsKeyPairGen,
            CKM_DH_PKCS_PARAMETER_GEN => MechanismType::DhPkcsParameterGen,
            CKM_DSA => MechanismType::Dsa,
            CKM_DSA_KEY_PAIR_GEN => MechanismType::DsaKeyPairGen,
            CKM_DSA_PARAMETER_GEN => MechanismType::DsaParameterGen,
            CKM_DSA_PROBABLISTIC_PARAMETER_GEN => MechanismType::DsaProbablisticParameterGen,
            CKM_DSA_SHA1 => MechanismType::DsaSha1,
            CKM_DSA_SHA224 => MechanismType::DsaSha224,
            CKM_DSA_SHA256 => MechanismType::DsaSha256,
            CKM_DSA_SHA384 => MechanismType::DsaSha384,
            CKM_DSA_SHA512 => MechanismType::DsaSha512,
            CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN => MechanismType::DsaShaweTaylorParameterGen,
            CKM_ECDH1_DERIVE => MechanismType::Ecdh1Derive,
            CKM_ECDH1_COFACTOR_DERIVE => MechanismType::Ecdh1CofactorDerive,
            CKM_ECDH_AES_KEY_WRAP => MechanismType::EcdhAesKeyWrap,
            CKM_ECDSA => MechanismType::Ecdsa,
            CKM_ECDSA_KEY_PAIR_GEN => MechanismType::EcdsaKeyPairGen,
            CKM_ECDSA_SHA1 => MechanismType::EcdsaSha1,
            CKM_ECDSA_SHA224 => MechanismType::EcdsaSha224,
            CKM_ECDSA_SHA256 => MechanismType::EcdsaSha256,
            CKM_ECDSA_SHA384 => MechanismType::EcdsaSha384,
            CKM_ECDSA_SHA512 => MechanismType::EcdsaSha512,
            CKM_ECMQV_DERIVE => MechanismType::EcmqvDerive,
            CKM_EXTRACT_KEY_FROM_KEY => MechanismType::ExtractKeyFromKey,
            CKM_FASTHASH => MechanismType::Fasthash,
            CKM_FORTEZZA_TIMESTAMP => MechanismType::FortezzaTimestamp,
            CKM_GENERIC_SECRET_KEY_GEN => MechanismType::GenericSecretKeyGen,
            CKM_GOST28147_KEY_GEN => MechanismType::Gost28147KeyGen,
            CKM_GOST28147_ECB => MechanismType::Gost28147Ecb,
            CKM_GOST28147 => MechanismType::Gost28147,
            CKM_GOST28147_MAC => MechanismType::Gost28147Mac,
            CKM_GOST28147_KEY_WRAP => MechanismType::Gost28147KeyWrap,
            CKM_GOSTR3410_KEY_PAIR_GEN => MechanismType::Gostr3410KeyPairGen,
            CKM_GOSTR3410 => MechanismType::Gostr3410,
            CKM_GOSTR3410_KEY_WRAP => MechanismType::Gostr3410KeyWrap,
            CKM_GOSTR3410_DERIVE => MechanismType::Gostr3410Derive,
            CKM_GOSTR3411 => MechanismType::Gostr3411,
            CKM_GOSTR3411_HMAC => MechanismType::Gostr3411Hmac,
            CKM_GOSTR3410_WITH_GOSTR3411 => MechanismType::Gostr3410WithGostr3411,
            CKM_HOTP => MechanismType::Hotp,
            CKM_HOTP_KEY_GEN => MechanismType::HotpKeyGen,
            CKM_IDEA_CBC => MechanismType::IdeaCbc,
            CKM_IDEA_CBC_PAD => MechanismType::IdeaCbcPad,
            CKM_IDEA_ECB => MechanismType::IdeaEcb,
            CKM_IDEA_KEY_GEN => MechanismType::IdeaKeyGen,
            CKM_IDEA_MAC => MechanismType::IdeaMac,
            CKM_IDEA_MAC_GENERAL => MechanismType::IdeaMacGeneral,
            CKM_JUNIPER_CBC128 => MechanismType::JuniperCbc128,
            CKM_JUNIPER_COUNTER => MechanismType::JuniperCounter,
            CKM_JUNIPER_ECB128 => MechanismType::JuniperEcb128,
            CKM_JUNIPER_KEY_GEN => MechanismType::JuniperKeyGen,
            CKM_JUNIPER_SHUFFLE => MechanismType::JuniperShuffle,
            CKM_JUNIPER_WRAP => MechanismType::JuniperWrap,
            CKM_KEA_DERIVE => MechanismType::KeaDerive,
            CKM_KEA_KEY_DERIVE => MechanismType::KeaKeyDerive,
            CKM_KEA_KEY_PAIR_GEN => MechanismType::KeaKeyPairGen,
            CKM_KEY_WRAP_LYNKS => MechanismType::KeyWrapLynks,
            CKM_KEY_WRAP_SET_OAEP => MechanismType::KeyWrapSetOaep,
            CKM_KIP_DERIVE => MechanismType::KipDerive,
            CKM_KIP_MAC => MechanismType::KipMac,
            CKM_KIP_WRAP => MechanismType::KipWrap,
            CKM_MD2_RSA_PKCS => MechanismType::Md2RsaPkcs,
            CKM_MD2 => MechanismType::Md2,
            CKM_MD2_HMAC => MechanismType::Md2Hmac,
            CKM_MD2_HMAC_GENERAL => MechanismType::Md2HmacGeneral,
            CKM_MD2_KEY_DERIVATION => MechanismType::Md2KeyDerivation,
            CKM_MD5_RSA_PKCS => MechanismType::Md5RsaPkcs,
            CKM_MD5 => MechanismType::Md5,
            CKM_MD5_HMAC => MechanismType::Md5Hmac,
            CKM_MD5_HMAC_GENERAL => MechanismType::Md5HmacGeneral,
            CKM_MD5_KEY_DERIVATION => MechanismType::Md5KeyDerivation,
            CKM_PBA_SHA1_WITH_SHA1_HMAC => MechanismType::PbaSha1WithSha1Hmac,
            CKM_PBE_MD2_DES_CBC => MechanismType::PbeMd2DesCbc,
            CKM_PBE_MD5_DES_CBC => MechanismType::PbeMd5DesCbc,
            CKM_PBE_MD5_CAST_CBC => MechanismType::PbeMd5CastCbc,
            CKM_PBE_MD5_CAST3_CBC => MechanismType::PbeMd5Cast3Cbc,
            CKM_PBE_MD5_CAST5_CBC => MechanismType::PbeMd5Cast5Cbc,
            CKM_PBE_SHA1_CAST5_CBC => MechanismType::PbeSha1Cast5Cbc,
            CKM_PBE_SHA1_DES2_EDE_CBC => MechanismType::PbeSha1Des2EdeCbc,
            CKM_PBE_SHA1_DES3_EDE_CBC => MechanismType::PbeSha1Des3EdeCbc,
            CKM_PBE_SHA1_RC2_40_CBC => MechanismType::PbeSha1Rc2_40Cbc,
            CKM_PBE_SHA1_RC2_128_CBC => MechanismType::PbeSha1Rc2_128Cbc,
            CKM_PBE_SHA1_RC4_40 => MechanismType::PbeSha1Rc4_40,
            CKM_PBE_SHA1_RC4_128 => MechanismType::PbeSha1Rc4_128,
            CKM_PKCS5_PBKD2 => MechanismType::Pkcs5Pbkd2,
            CKM_RC2_KEY_GEN => MechanismType::Rc2KeyGen,
            CKM_RC2_ECB => MechanismType::Rc2Ecb,
            CKM_RC2_CBC => MechanismType::Rc2Cbc,
            CKM_RC2_MAC => MechanismType::Rc2Mac,
            CKM_RC2_MAC_GENERAL => MechanismType::Rc2MacGeneral,
            CKM_RC2_CBC_PAD => MechanismType::Rc2CbcPad,
            CKM_RC4_KEY_GEN => MechanismType::Rc4KeyGen,
            CKM_RC4 => MechanismType::Rc4,
            CKM_RC5_KEY_GEN => MechanismType::Rc5KeyGen,
            CKM_RC5_ECB => MechanismType::Rc5Ecb,
            CKM_RC5_CBC => MechanismType::Rc5Cbc,
            CKM_RC5_MAC => MechanismType::Rc5Mac,
            CKM_RC5_MAC_GENERAL => MechanismType::Rc5MacGeneral,
            CKM_RC5_CBC_PAD => MechanismType::Rrc5CbcPad,
            CKM_RIPEMD128_RSA_PKCS => MechanismType::Ripemd128RsaPkcs,
            CKM_RIPEMD128 => MechanismType::Ripemd128,
            CKM_RIPEMD128_HMAC => MechanismType::Ripemd128Hmac,
            CKM_RIPEMD128_HMAC_GENERAL => MechanismType::Ripemd128HmacGeneral,
            CKM_RIPEMD160_RSA_PKCS => MechanismType::Ripemd160RsaPkcs,
            CKM_RIPEMD160 => MechanismType::Ripemd160,
            CKM_RIPEMD160_HMAC => MechanismType::Ripemd160Hmac,
            CKM_RIPEMD160_HMAC_GENERAL => MechanismType::Ripemd160HmacGeneral,
            CKM_RSA_9796 => MechanismType::Rsa9796,
            CKM_RSA_AES_KEY_WRAP => MechanismType::RsaAesKeyWrap,
            CKM_RSA_PKCS => MechanismType::RsaPkcs,
            CKM_RSA_PKCS_KEY_PAIR_GEN => MechanismType::RsaPkcsKeyPairGen,
            CKM_RSA_PKCS_OAEP => MechanismType::RsaPkcsOaep,
            CKM_RSA_PKCS_OAEP_TPM_1_1 => MechanismType::RsaPkcsOaepTpm11,
            CKM_RSA_PKCS_PSS => MechanismType::RsaPkcsPss,
            CKM_RSA_PKCS_TPM_1_1 => MechanismType::RsaPkcsTpm11,
            CKM_RSA_X9_31_KEY_PAIR_GEN => MechanismType::RsaX9_31KeyPairGen,
            CKM_RSA_X9_31 => MechanismType::RsaX9_31,
            CKM_RSA_X_509 => MechanismType::RsaX509,
            CKM_SECURID => MechanismType::Securid,
            CKM_SECURID_KEY_GEN => MechanismType::SecuridKeyGen,
            CKM_SEED_CBC => MechanismType::SeedCbc,
            CKM_SEED_CBC_ENCRYPT_DATA => MechanismType::SeedCbcEncryptData,
            CKM_SEED_CBC_PAD => MechanismType::SeedCbcPad,
            CKM_SEED_ECB => MechanismType::SeedEcb,
            CKM_SEED_ECB_ENCRYPT_DATA => MechanismType::SeedEcbEncryptData,
            CKM_SEED_KEY_GEN => MechanismType::SeedKeyGen,
            CKM_SEED_MAC => MechanismType::SeedMac,
            CKM_SEED_MAC_GENERAL => MechanismType::SeedMacGeneral,
            CKM_SHA1_RSA_PKCS => MechanismType::Sha1RsaPkcs,
            CKM_SHA1_RSA_PKCS_PSS => MechanismType::Sha1RsaPkcsPss,
            CKM_SHA1_KEY_DERIVATION => MechanismType::Sha1KeyDerivation,
            CKM_SHA224_RSA_PKCS => MechanismType::Sha224RsaPkcs,
            CKM_SHA224_RSA_PKCS_PSS => MechanismType::Sha224RsaPkcsPss,
            CKM_SHA224 => MechanismType::Sha224,
            CKM_SHA224_HMAC => MechanismType::Sha224Hmac,
            CKM_SHA224_HMAC_GENERAL => MechanismType::Sha224HmacGeneral,
            CKM_SHA224_KEY_DERIVATION => MechanismType::Sha224KeyDerivation,
            CKM_SHA256_RSA_PKCS => MechanismType::Sha256RsaPkcs,
            CKM_SHA256_RSA_PKCS_PSS => MechanismType::Sha256RsaPkcsPss,
            CKM_SHA256 => MechanismType::Sha256,
            CKM_SHA256_HMAC => MechanismType::Sha256Hmac,
            CKM_SHA256_HMAC_GENERAL => MechanismType::Sha256HmacGeneral,
            CKM_SHA256_KEY_DERIVATION => MechanismType::Sha256KeyDerivation,
            CKM_SHA384_RSA_PKCS => MechanismType::Sha384RsaPkcs,
            CKM_SHA384_RSA_PKCS_PSS => MechanismType::Sha384RsaPkcsPss,
            CKM_SHA384 => MechanismType::Sha384,
            CKM_SHA384_HMAC => MechanismType::Sha384Hmac,
            CKM_SHA384_HMAC_GENERAL => MechanismType::Sha384HmacGeneral,
            CKM_SHA384_KEY_DERIVATION => MechanismType::Sha384KeyDerivation,
            CKM_SHA512_RSA_PKCS => MechanismType::Sha512RsaPkcs,
            CKM_SHA512_RSA_PKCS_PSS => MechanismType::Sha512RsaPkcsPss,
            CKM_SHA512_T => MechanismType::Sha512T,
            CKM_SHA512_T_HMAC => MechanismType::Sha512THmac,
            CKM_SHA512_T_HMAC_GENERAL => MechanismType::Sha512THmacGeneral,
            CKM_SHA512_T_KEY_DERIVATION => MechanismType::Sha512TKeyDerivation,
            CKM_SHA512 => MechanismType::Sha512,
            CKM_SHA512_HMAC => MechanismType::Sha512Hmac,
            CKM_SHA512_HMAC_GENERAL => MechanismType::Sha512HmacGeneral,
            CKM_SHA512_KEY_DERIVATION => MechanismType::Sha512KeyDerivation,
            CKM_SHA1_RSA_X9_31 => MechanismType::Sha1RsaX9_31,
            CKM_SHA512_224 => MechanismType::Sha512_224,
            CKM_SHA512_224_HMAC => MechanismType::Sha512_224Hmac,
            CKM_SHA512_224_HMAC_GENERAL => MechanismType::Sha512_224HmacGeneral,
            CKM_SHA512_224_KEY_DERIVATION => MechanismType::Sha512_224KeyDerivation,
            CKM_SHA512_256 => MechanismType::Sha512_256,
            CKM_SHA512_256_HMAC => MechanismType::Sha512_256Hmac,
            CKM_SHA512_256_HMAC_GENERAL => MechanismType::Sha512_256HmacGeneral,
            CKM_SHA512_256_KEY_DERIVATION => MechanismType::Sha512_256KeyDerivation,
            CKM_SHA_1 => MechanismType::Sha1,
            CKM_SHA_1_HMAC => MechanismType::Sha1Hmac,
            CKM_SHA_1_HMAC_GENERAL => MechanismType::Sha1HmacGeneral,
            CKM_SKIPJACK_CBC64 => MechanismType::SkipjackCbc64,
            CKM_SKIPJACK_CFB8 => MechanismType::SkipjackCfb8,
            CKM_SKIPJACK_CFB16 => MechanismType::SkipjackCfb16,
            CKM_SKIPJACK_CFB32 => MechanismType::SkipjackCfb32,
            CKM_SKIPJACK_CFB64 => MechanismType::SkipjackCfb64,
            CKM_SKIPJACK_ECB64 => MechanismType::SkipjackEcb64,
            CKM_SKIPJACK_KEY_GEN => MechanismType::SkipjackKeyGen,
            CKM_SKIPJACK_OFB64 => MechanismType::SkipjackOfb64,
            CKM_SKIPJACK_PRIVATE_WRAP => MechanismType::SkipjackPrivateWrap,
            CKM_SKIPJACK_RELAYX => MechanismType::SkipjackRelayx,
            CKM_SKIPJACK_WRAP => MechanismType::SkipjackWrap,
            CKM_SSL3_PRE_MASTER_KEY_GEN => MechanismType::Ssl3PreMasterKeyGen,
            CKM_SSL3_MASTER_KEY_DERIVE => MechanismType::Ssl3MasterKeyDerive,
            CKM_SSL3_KEY_AND_MAC_DERIVE => MechanismType::Ssl3KeyAndMacDerive,
            CKM_SSL3_MASTER_KEY_DERIVE_DH => MechanismType::Ssl3MasterKeyDeriveDh,
            CKM_SSL3_MD5_MAC => MechanismType::Ssl3Md5Mac,
            CKM_SSL3_SHA1_MAC => MechanismType::Ssl3Sha1Mac,
            CKM_TLS10_MAC_SERVER => MechanismType::Tls10MacServer,
            CKM_TLS10_MAC_CLIENT => MechanismType::Tls10MacClient,
            CKM_TLS12_MAC => MechanismType::Tls12Mac,
            CKM_TLS12_KDF => MechanismType::Tls12Kdf,
            CKM_TLS12_MASTER_KEY_DERIVE => MechanismType::Tls12MasterKeyDerive,
            CKM_TLS12_KEY_AND_MAC_DERIVE => MechanismType::Tls12KeyAndMacDerive,
            CKM_TLS12_MASTER_KEY_DERIVE_DH => MechanismType::Tls12MasterKeyDeriveDh,
            CKM_TLS12_KEY_SAFE_DERIVE => MechanismType::Tls12KeySafeDerive,
            CKM_TLS_KDF => MechanismType::TlsKdf,
            CKM_TLS_KEY_AND_MAC_DERIVE => MechanismType::TlsKeyAndMacDerive,
            CKM_TLS_MAC => MechanismType::TlsMac,
            CKM_TLS_MASTER_KEY_DERIVE => MechanismType::TlsMasterKeyDerive,
            CKM_TLS_MASTER_KEY_DERIVE_DH => MechanismType::TlsMasterKeyDeriveDh,
            CKM_TLS_PRE_MASTER_KEY_GEN => MechanismType::TlsPreMasterKeyGen,
            CKM_TLS_PRF => MechanismType::TlsPrf,
            CKM_TWOFISH_CBC => MechanismType::TwofishCbc,
            CKM_TWOFISH_CBC_PAD => MechanismType::TwofishCbcPad,
            CKM_TWOFISH_KEY_GEN => MechanismType::TwofishKeyGen,
            CKM_VENDOR_DEFINED => MechanismType::VendorDefined,
            CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE => MechanismType::WtlsClientKeyAndMacDerive,
            CKM_WTLS_MASTER_KEY_DERIVE => MechanismType::WtlsMasterKeyDerive,
            CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC => MechanismType::WtlsMasterKeyDeriveDhEcc,
            CKM_WTLS_PRE_MASTER_KEY_GEN => MechanismType::WtlsPreMasterKeyGen,
            CKM_WTLS_PRF => MechanismType::WtlsPrf,
            CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE => MechanismType::WtlsServerKeyAndMacDerive,
            CKM_X9_42_DH_KEY_PAIR_GEN => MechanismType::X9_42DhKeyPairGen,
            CKM_X9_42_DH_DERIVE => MechanismType::X9_42DhDerive,
            CKM_X9_42_DH_HYBRID_DERIVE => MechanismType::X9_42DhHybridDerive,
            CKM_X9_42_MQV_DERIVE => MechanismType::X9_42MqvDerive,
            CKM_X9_42_DH_PARAMETER_GEN => MechanismType::X9_42DhParameterGen,
            CKM_XOR_BASE_AND_DATA => MechanismType::XorBaseAndData,
            m => panic!("Unknown mechanism type {}", m),
        }
    }
}
