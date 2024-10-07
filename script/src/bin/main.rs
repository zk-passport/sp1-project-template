//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use clap::Parser;
// use fibonacci_lib::PublicValuesStruct;
use sp1_sdk::{ProverClient, SP1Stdin};
use std::fs::File;
use std::io::Read;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long, default_value = "20")]
    n: u32,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::new();

    // Read the serialized byte arrays directly from the files
    let spartan_inst_bytes: Vec<u8> = std::fs::read("spartan_inst.bin").unwrap();
    let proof_bytes: Vec<u8> = std::fs::read("proof.bin").unwrap();
    let inputs_bytes: Vec<u8> = std::fs::read("inputs.bin").unwrap();

    // Prepare the inputs to the SP1 program
    let mut stdin = SP1Stdin::new();
    stdin.write(&spartan_inst_bytes);
    stdin.write(&proof_bytes);
    stdin.write(&inputs_bytes);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(FIBONACCI_ELF, stdin).run().unwrap();
        println!("Program executed successfully.");
        println!("report: {}", report);
        println!("output: {:?}", output);

        // Check if the output is one
        let output_slice = output.as_slice();
        if !output_slice.is_empty() && output_slice[0] == 1 {
            println!("Success.");
        } else {
            println!("Failed.");
        }

        // Read the output.
        // let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
        // let PublicValuesStruct { n, a, b } = decoded;
        // println!("n: {}", n);
        // println!("a: {}", a);
        // println!("b: {}", b);

        // let (expected_a, expected_b) = fibonacci_lib::fibonacci(n);
        // assert_eq!(a, expected_a);
        // assert_eq!(b, expected_b);
        // println!("Values are correct!");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(FIBONACCI_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
