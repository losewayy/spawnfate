//! Ground-truth argv probe: selftest materializes PE files as copies of this
//! binary, so the child's actual argv comes back on stdout — that's what a
//! predicted `Runs { argv }` is compared against.
//! Prints argv as a JSON array on one line, prefixed for the harness.
fn main() {
    let argv: Vec<String> = std::env::args().collect();
    println!("ARGVPAYLOAD{}", serde_json::to_string(&argv).unwrap());
}
