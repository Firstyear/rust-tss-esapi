
use crate::{
    Result,
    structures::buffers::label::Label
};
use crate::tss2_esys::TPMS_DERIVE;


/// Structure holding key derivation parameters
///
/// # Details
/// This corresponds to TPMS_DERIVE
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derive {
    label: Label,
    context: Label,
}

impl Derive {
    pub fn from_bytes(label: &[u8], context: &[u8]) -> Result<Self> {
        let label = Label::from_bytes(label)?;
        let context = Label::from_bytes(context)?;

        Ok(Self {
            label, context
        })
    }
}

impl From<Derive> for TPMS_DERIVE {
    fn from(derive: Derive) -> Self {
        TPMS_DERIVE {
            label: derive.label.into(),
            context: derive.context.into(),
        }
    }
}
