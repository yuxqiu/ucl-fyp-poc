use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use hash_to_field::from_base_field::FromBaseFieldGadget;
use map_to_curve::to_base_field::ToBaseFieldGadget;

pub mod hash_to_curve;
pub mod hash_to_field;
pub mod map_to_curve;

// Marker trait for types that can operate with hash to curve gadget
// - HashCurveGroup: the group that is hashed to
// - Fp: the prime field the field var operates on
pub trait HashToCurveOpBound<HashCurveGroup: CurveGroup, Fp: PrimeField>:
    FromBaseFieldGadget<Fp>
    + ToBaseFieldGadget<<HashCurveGroup::BaseField as Field>::BasePrimeField, Fp>
{
}
