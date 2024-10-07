// Verifies Spartan over BN-254
#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::io::{commit, read};

use libspartan::{InputsAssignment, Instance, NIZKGens, NIZK};
use merlin::Transcript;

pub fn main() {
    // Read the serialized data from inputs
    let spartan_inst_bytes: Vec<u8> = read();
    let proof_bytes: Vec<u8> = read();
    let inputs_bytes: Vec<u8> = read();

    // Deserialize spartan_inst
    let spartan_inst: Instance =
        bincode::deserialize(&spartan_inst_bytes).expect("Failed to deserialize instance");

    // Deserialize proof
    let proof: NIZK = bincode::deserialize(&proof_bytes).expect("Failed to deserialize proof");

    // Deserialize inputs
    let inputs: InputsAssignment =
        bincode::deserialize(&inputs_bytes).expect("Failed to deserialize inputs");

    // Initialize the generators
    let gens = NIZKGens::new(
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
