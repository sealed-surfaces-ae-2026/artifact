use std::io::{Read, Write};

fn main() {
    let mut source = Vec::new();
    std::io::stdin().read_to_end(&mut source).unwrap();
    let text = std::str::from_utf8(&source).expect("DSL L source must be UTF-8");
    let program = dsl_l::read_program(text, "<sealed-source>").expect("DSL L read failed");
    let core = dsl_l::normalize_program(&program.datums, "<sealed-source>")
        .expect("DSL L normalization failed");
    let bytes = dsl_l::canonical_program_bytes(&core).expect("canonical Core failed");
    std::io::stdout().write_all(&bytes).unwrap();
}
