// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#[allow(unused_macros)]
macro_rules! named_field_buffer_type {
    ($native_type:ident,$MAX:expr,$tss_type:ident,$buffer_field_name:ident) => {
        use crate::tss2_esys::$tss_type;
        use crate::{Error, Result, WrapperErrorKind};
        use log::error;
        use std::convert::TryFrom;
        use std::ops::Deref;
        use zeroize::Zeroizing;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $native_type(Zeroizing<Vec<u8>>);

        impl Default for $native_type {
            fn default() -> Self {
                $native_type(Vec::new().into())
            }
        }

        impl $native_type {
            pub const MAX_SIZE: usize = $MAX;

            pub fn value(&self) -> &[u8] {
                &self.0
            }
        }

        impl Deref for $native_type {
            type Target = Vec<u8>;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl TryFrom<Vec<u8>> for $native_type {
            type Error = Error;

            fn try_from(bytes: Vec<u8>) -> Result<Self> {
                if bytes.len() > Self::MAX_SIZE {
                    error!("Error: Invalid Vec<u8> size(> {})", Self::MAX_SIZE);
                    return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
                }
                Ok($native_type(bytes.into()))
            }
        }

        impl TryFrom<&[u8]> for $native_type {
            type Error = Error;

            fn try_from(bytes: &[u8]) -> Result<Self> {
                if bytes.len() > Self::MAX_SIZE {
                    error!("Error: Invalid &[u8] size(> {})", Self::MAX_SIZE);
                    return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
                }
                Ok($native_type(bytes.to_vec().into()))
            }
        }

        impl TryFrom<$tss_type> for $native_type {
            type Error = Error;

            fn try_from(tss: $tss_type) -> Result<Self> {
                let size = tss.size as usize;
                if size > Self::MAX_SIZE {
                    error!("Error: Invalid buffer size(> {})", Self::MAX_SIZE);
                    return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
                }
                Ok($native_type(tss.$buffer_field_name[..size].to_vec().into()))
            }
        }

        impl From<$native_type> for $tss_type {
            fn from(native: $native_type) -> Self {
                let mut buffer = $tss_type {
                    size: native.0.len() as u16,
                    ..Default::default()
                };
                buffer.$buffer_field_name[..native.0.len()].copy_from_slice(&native.0);
                buffer
            }
        }
    };
}

#[allow(unused_macros)]
macro_rules! buffer_type {
    ($native_type:ident,$MAX:expr,$tss_type:ident) => {
        named_field_buffer_type!($native_type, $MAX, $tss_type, buffer);
    };
}

pub mod public;

pub mod auth {
    buffer_type!(Auth, 64, TPM2B_AUTH);
}

pub mod data {
    buffer_type!(Data, 64, TPM2B_DATA);
}

pub mod sensitive_data {
    buffer_type!(SensitiveData, 256, TPM2B_SENSITIVE_DATA);
}

pub mod private {
    buffer_type!(Private, 256, TPM2B_PRIVATE);
}

pub mod encrypted_secret {
    named_field_buffer_type!(EncryptedSecret, 256, TPM2B_ENCRYPTED_SECRET, secret);
}

pub mod id_object {
    named_field_buffer_type!(IDObject, 256, TPM2B_ID_OBJECT, credential);
}

pub mod digest {
    buffer_type!(Digest, 64, TPM2B_DIGEST);

    // Some implementations to get from Digest to [u8; N] for common values of N (sha* primarily)
    // This is used to work around the fact that Rust does not allow custom functions for general values of N in [T; N],
    //  and the standard try_from for Slice to Array is only for LengthAtMost32.
    use std::convert::TryInto;

    // For the arrays that are LengthAtMost32, we use the built-in try_from
    impl TryFrom<Digest> for [u8; 20] {
        type Error = Error;

        fn try_from(value: Digest) -> Result<Self> {
            value
                .value()
                .try_into()
                .map_err(|_| Error::local_error(WrapperErrorKind::WrongParamSize))
        }
    }

    impl TryFrom<Digest> for [u8; 32] {
        type Error = Error;

        fn try_from(value: Digest) -> Result<Self> {
            value
                .value()
                .try_into()
                .map_err(|_| Error::local_error(WrapperErrorKind::WrongParamSize))
        }
    }

    // For the others, we build our own
    impl TryFrom<Digest> for [u8; 48] {
        type Error = Error;

        fn try_from(value: Digest) -> Result<Self> {
            if value.value().len() != 48 {
                return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
            }

            let mut result = [0; 48];

            result.copy_from_slice(value.value());

            Ok(result)
        }
    }

    impl TryFrom<Digest> for [u8; 64] {
        type Error = Error;

        fn try_from(value: Digest) -> Result<Self> {
            if value.value().len() != 64 {
                return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
            }

            let mut result = [0; 64];

            result.copy_from_slice(value.value());

            Ok(result)
        }
    }
}

pub mod max_buffer {
    use crate::tss2_esys::TPM2_MAX_DIGEST_BUFFER;
    buffer_type!(MaxBuffer, TPM2_MAX_DIGEST_BUFFER as usize, TPM2B_MAX_BUFFER);
}

pub mod max_nv_buffer {
    use crate::tss2_esys::TPM2_MAX_NV_BUFFER_SIZE;
    buffer_type!(
        MaxNvBuffer,
        TPM2_MAX_NV_BUFFER_SIZE as usize,
        TPM2B_MAX_NV_BUFFER
    );
}

pub mod nonce {
    buffer_type!(Nonce, 64, TPM2B_NONCE);
}

pub mod public_key_rsa {
    use crate::{interface_types::key_bits::RsaKeyBits, tss2_esys::TPM2_MAX_RSA_KEY_BYTES};
    buffer_type!(
        PublicKeyRsa,
        TPM2_MAX_RSA_KEY_BYTES as usize,
        TPM2B_PUBLIC_KEY_RSA
    );

    impl PublicKeyRsa {
        pub fn new_empty_with_size(rsa_key_bits: RsaKeyBits) -> Self {
            match rsa_key_bits {
                RsaKeyBits::Rsa1024 => PublicKeyRsa(vec![0u8; 128].into()),
                RsaKeyBits::Rsa2048 => PublicKeyRsa(vec![0u8; 256].into()),
                RsaKeyBits::Rsa3072 => PublicKeyRsa(vec![0u8; 384].into()),
                RsaKeyBits::Rsa4096 => PublicKeyRsa(vec![0u8; 512].into()),
            }
        }
    }

    impl TryFrom<PublicKeyRsa> for [u8; 128] {
        type Error = Error;

        fn try_from(public_key_rsa: PublicKeyRsa) -> Result<Self> {
            if public_key_rsa.value().len() > 128 {
                return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
            }

            let mut value = [0u8; 128];
            value.copy_from_slice(public_key_rsa.value());
            Ok(value)
        }
    }

    impl TryFrom<PublicKeyRsa> for [u8; 256] {
        type Error = Error;

        fn try_from(public_key_rsa: PublicKeyRsa) -> Result<Self> {
            if public_key_rsa.value().len() > 256 {
                return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
            }

            let mut value = [0u8; 256];
            value.copy_from_slice(public_key_rsa.value());
            Ok(value)
        }
    }

    impl TryFrom<PublicKeyRsa> for [u8; 384] {
        type Error = Error;

        fn try_from(public_key_rsa: PublicKeyRsa) -> Result<Self> {
            if public_key_rsa.value().len() > 384 {
                return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
            }

            let mut value = [0u8; 384];
            value.copy_from_slice(public_key_rsa.value());
            Ok(value)
        }
    }

    impl TryFrom<PublicKeyRsa> for [u8; 512] {
        type Error = Error;

        fn try_from(public_key_rsa: PublicKeyRsa) -> Result<Self> {
            if public_key_rsa.value().len() > 512 {
                return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
            }

            let mut value = [0u8; 512];
            value.copy_from_slice(public_key_rsa.value());
            Ok(value)
        }
    }
}

pub mod timeout {
    buffer_type!(Timeout, 8, TPM2B_TIMEOUT);
}

pub mod initial_value {
    buffer_type!(
        InitialValue,
        crate::tss2_esys::TPM2_MAX_SYM_BLOCK_SIZE as usize,
        TPM2B_IV
    );
}

pub mod ecc_parameter {
    buffer_type!(
        EccParameter,
        crate::tss2_esys::TPM2_MAX_ECC_KEY_BYTES as usize,
        TPM2B_ECC_PARAMETER
    );
}
