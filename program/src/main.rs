// Verifies Spartan over BN-254
#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::io::{commit, read};

use ark_bn254::{Fr, G1Projective};
use ark_serialize::CanonicalDeserialize;
use libspartan::{r1csinstance::R1CSInstance, InputsAssignment, Instance, NIZKGens, NIZK};
use merlin::Transcript;

pub fn main() {
    // Read the serialized data from inputs
    let spartan_inst_bytes: Vec<u8> = read();
    let proof_bytes: Vec<u8> = read();
    let inputs_bytes: Vec<u8> = read();

    // Deserialize spartan_inst
    let spartan_inst = {
        let mut reader = &spartan_inst_bytes[..];
        let inner_inst = R1CSInstance::deserialize_compressed(&mut reader)
            .expect("Failed to deserialize instance");
        Instance::from_r1cs_instance(inner_inst)
    };

    // Deserialize proof
    let proof = {
        let mut reader = &proof_bytes[..];
        NIZK::<G1Projective>::deserialize_compressed(&mut reader)
            .expect("Failed to deserialize proof")
    };

    // Deserialize inputs
    let inputs = {
        let mut reader = &inputs_bytes[..];
        let assignment =
            Vec::<Fr>::deserialize_compressed(&mut reader).expect("Failed to deserialize inputs");
        InputsAssignment::new(&assignment).expect("Failed to create InputsAssignment")
    };

    // Initialize the generators
    let gens = NIZKGens::<G1Projective>::new(
        spartan_inst.inst.get_num_cons(),
        spartan_inst.inst.get_num_vars(),
        spartan_inst.inst.get_num_inputs(),
    );

    // Verify the proof
    let mut verifier_transcript = Transcript::new(b"nizk_example");
    let result = proof.verify(&spartan_inst, &inputs, &mut verifier_transcript, &gens);

    // Output the result
    let success = result.is_ok();
    commit(&success);
}
