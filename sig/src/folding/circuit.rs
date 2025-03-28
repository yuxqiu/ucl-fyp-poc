use std::{cmp::Ordering, marker::PhantomData};

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    convert::ToConstraintFieldGadget,
    eq::EqGadget,
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar, FieldVar},
    groups::{bls12::G1Var, CurveVar},
    prelude::Boolean,
    uint64::UInt64,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::{frontend::FCircuit, Error};

use crate::{
    bc::{
        block::{Block, QuorumSignature},
        params::STRONG_THRESHOLD,
    },
    bls::{BLSAggregateSignatureVerifyGadget, Parameters, ParametersVar, PublicKeyVar},
    folding::bc::{CommitteeVar, QuorumSignatureVar},
    params::BlsSigConfig,
};

use super::{
    bc::BlockVar, from_constraint_field::FromConstraintFieldGadget, serialize::SerializeGadget,
};

#[derive(Clone, Copy, Debug)]
pub struct BCCircuitNoMerkle<CF: PrimeField> {
    params: Parameters<BlsSigConfig>,
    _cf: PhantomData<CF>,
}

impl<CF: PrimeField> FCircuit<CF> for BCCircuitNoMerkle<CF> {
    type Params = Parameters<BlsSigConfig>;
    type ExternalInputs = Block;
    type ExternalInputsVar = BlockVar<CF>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            params,
            _cf: PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        CommitteeVar::<CF>::num_constraint_var_needed() + 1
    }

    /// generates the constraints for the step of F for the given z_i
    #[tracing::instrument(skip_all)]
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<CF>,
        _: usize,
        z_i: Vec<FpVar<CF>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<CF>>, SynthesisError> {
        tracing::info!("start reconstructing committee and epoch");

        // reconstruct epoch and committee from z_i
        let mut iter = z_i.into_iter();
        let committee = CommitteeVar::from_constraint_field(iter.by_ref())?;
        let epoch = UInt64::from_constraint_field(iter.by_ref())?;

        tracing::info!(num_constraints = cs.num_constraints());

        // 1. enforce epoch of new committee = epoch of old committee + 1
        tracing::info!("start enforcing epoch of new committee = epoch of old committee + 1");

        external_inputs
            .epoch
            .is_eq(&(epoch.wrapping_add(&UInt64::constant(1))))?
            .enforce_equal(&Boolean::TRUE)?;

        tracing::info!(num_constraints = cs.num_constraints());

        // 2. enforce the signature matches
        tracing::info!("start enforcing signature matches");
        let sig = &external_inputs.sig.sig;
        let signers = &external_inputs.sig.signers;

        // 2.1 aggregate public keys
        tracing::info!("start aggregating public keys");

        let mut weight = UInt64::constant(0);
        let mut aggregate_pk = G1Var::<BlsSigConfig, EmulatedFpVar<_, CF>, CF>::zero();
        for (signed, signer) in signers.iter().zip(committee.committee) {
            let pk = signed.select(
                &(signer.pk.pub_key),
                &G1Var::<BlsSigConfig, EmulatedFpVar<_, CF>, CF>::zero(),
            )?;
            let w = signed.select(&(signer.weight), &UInt64::constant(0))?;
            aggregate_pk += pk;
            weight.wrapping_add_in_place(&w);
        }
        let aggregate_pk = PublicKeyVar {
            pub_key: aggregate_pk,
        };

        tracing::info!(num_constraints = cs.num_constraints());

        // 2.2 check signature
        tracing::info!("start checking signatures");

        let params = ParametersVar::new_constant(cs.clone(), self.params)?;
        let mut external_inputs_without_sig = external_inputs.clone();
        external_inputs_without_sig.sig =
            QuorumSignatureVar::new_constant(cs.clone(), QuorumSignature::default())?;
        BLSAggregateSignatureVerifyGadget::verify(
            &params,
            &aggregate_pk,
            &external_inputs_without_sig.serialize()?,
            sig,
        )?;

        tracing::info!(num_constraints = cs.num_constraints());

        // 2.3 check weight > threshold
        tracing::info!("start checking weight > threshold");

        weight.to_fp()?.enforce_cmp(
            &FpVar::constant(STRONG_THRESHOLD.into()),
            Ordering::Greater,
            true,
        )?;

        tracing::info!(num_constraints = cs.num_constraints());

        // 3. return the new state
        tracing::info!("start returning the new state");

        let mut committee = external_inputs.committee.to_constraint_field()?;
        let epoch = external_inputs.epoch.to_fp()?;
        committee.push(epoch);

        tracing::info!(num_constraints = cs.num_constraints());

        Ok(committee)
    }
}
