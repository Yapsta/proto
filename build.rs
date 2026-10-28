//! Compiles `proto/` with protox (pure Rust: no system `protoc`, so the client
//! and bot repos build this crate as a git dependency on any host) and writes
//! the descriptor set the wire-surface test reads.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    let files = protox::compile(["yapsta/v1/yapsta.proto"], ["proto"])?;
    #[allow(
        clippy::disallowed_methods,
        reason = "a build script reads OUT_DIR from env"
    )]
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    std::fs::write(
        out.join("yapsta_v1.bin"),
        prost::Message::encode_to_vec(&files),
    )?;
    prost_build::Config::new().compile_fds(files)?;
    Ok(())
}
