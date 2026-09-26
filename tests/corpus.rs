//! Corpus runner — every YAML case in corpus/ executes against VirtualFs.
//! This is the machine-checkable half of spec-v0.md: a rule without a case
//! here is a claim, not a fact.

use spawnfate::corpus;

#[test]
fn corpus_cases() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let mut total = 0usize;
    let mut fails = Vec::new();
    for (_path, c) in corpus::load(&dir) {
        for case in &c.cases {
            total += 1;
            let (input, env, fs, target) = corpus::build(case);
            let report = spawnfate::analyze(&input, &env, &fs, target);
            fails.extend(corpus::check(case, &report));
        }
    }
    assert!(total > 0, "no corpus cases found");
    assert!(
        fails.is_empty(),
        "{} corpus failure(s):\n{}",
        fails.len(),
        fails.join("\n")
    );
    eprintln!("corpus: {total} cases passed");
}
