use anyhow::Error;
use ark_bls12_381::{Bls12_381, Fr as Scalar};
use ark_bw6_767::BW6_767;
use ark_crypto_primitives::snark::{constraints::SNARKGadget, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::fields::Field;
use ark_groth16::{
    constraints::Groth16VerifierGadget, r1cs_to_qap::LibsnarkReduction, Groth16, Proof, ProvingKey,
    VerifyingKey,
};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

type Fq = ark_bls12_381::Fq;

#[derive(Copy, Clone)]
struct InnerCircuit<F: Field> {
    a: F,
}

impl ConstraintSynthesizer<Scalar> for InnerCircuit<Scalar> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Scalar>) -> Result<(), SynthesisError> {
        let three = FpVar::new_constant(cs.clone(), Scalar::from(3))?;
        let a_var = FpVar::new_witness(cs.clone(), || Ok(self.a))?;
        a_var.enforce_equal(&three)
    }
}

#[derive(Clone)]
struct OuterSnarkCircuit {
    proof: Proof<Bls12_381>,
    vk: VerifyingKey<Bls12_381>,
}

type BlsPairingVar = ark_r1cs_std::pairing::bls12::PairingVar<ark_bls12_381::Config>;
type TestSNARK_bls = Groth16<Bls12_381>;
type TestSNARKGadget_bls = Groth16VerifierGadget<Bls12_381, BlsPairingVar>;

impl ConstraintSynthesizer<Fq> for OuterSnarkCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
        println!("ConstraintSynthesizer<Fq>");

        let input_gadget = <TestSNARKGadget_bls as SNARKGadget<
            <Bls12_381 as Pairing>::ScalarField,
            <Bls12_381 as Pairing>::BaseField,
            TestSNARK_bls,
        >>::InputVar::new_input(ns!(cs, "new_input"), || Ok(vec![]))?;

        let inner_proof_pub =
            <TestSNARKGadget_bls as SNARKGadget<
                <Bls12_381 as Pairing>::ScalarField,
                <Bls12_381 as Pairing>::BaseField,
                TestSNARK_bls,
            >>::ProofVar::new_input(ns!(cs, "alloc_proof"), || Ok(self.proof))?;

        let vk_gadget =
            <TestSNARKGadget_bls as SNARKGadget<
                <Bls12_381 as Pairing>::ScalarField,
                <Bls12_381 as Pairing>::BaseField,
                TestSNARK_bls,
            >>::VerifyingKeyVar::new_constant(ns!(cs, "alloc_vk"), self.vk.clone())?;

        <TestSNARKGadget_bls as SNARKGadget<
            <Bls12_381 as Pairing>::ScalarField,
            <Bls12_381 as Pairing>::BaseField,
            TestSNARK_bls,
        >>::verify(&vk_gadget, &input_gadget, &inner_proof_pub)?
        .enforce_equal(&Boolean::constant(true))?;

        Ok(())
    }
}

fn generate_outer_snark_proof() -> Result<(), Error> {
    let mut rng = &mut rand::thread_rng();

    let inner_circuit = InnerCircuit { a: Scalar::from(3) };

    let (pk, vk) = TestSNARK_bls::circuit_specific_setup(inner_circuit, &mut rng).unwrap();
    let proof = TestSNARK_bls::prove(&pk, inner_circuit.clone(), &mut rng).unwrap();

    assert!(
        TestSNARK_bls::verify(&vk, &vec![], &proof).unwrap(),
        "The native verification check fails."
    );

    let outer_circuit: OuterSnarkCircuit = OuterSnarkCircuit { proof, vk };

    println!("generate_random_parameters_with_reduction");
    let proving_key: ProvingKey<BW6_767> =
        Groth16::<BW6_767, LibsnarkReduction>::generate_random_parameters_with_reduction(
            outer_circuit.clone(),
            rng,
        )?;

    println!("create_random_proof_with_reduction");
    let _proof = Groth16::<BW6_767, LibsnarkReduction>::create_random_proof_with_reduction(
        outer_circuit,
        &proving_key,
        rng,
    )?;

    Ok(())
}

fn main() {
    println!("Hello, world!");

    generate_outer_snark_proof().unwrap();
}
