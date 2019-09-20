extern crate prost_build;

use std::env;
use std::path::Path;
use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};

pub fn main() {

    println!("cargo:rustc-link-search=native=lib");

    let mut config = prost_build::Config::new();
    config
        .compile_protos(
            &[
                "proto/captif.v1.proto",
                "proto/captif.proximity.v1.proto",
            ],
            &["proto"],
        )
        .unwrap();


    let cmd = Command::new("git")
        .args(&["describe", "--tags", "--always", "--dirty=-dirty"])
        .stderr(Stdio::inherit())
        .output().unwrap();
    let gitver = String::from_utf8_lossy(&cmd.stdout).to_owned();
    let gitver = gitver.trim();

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("build_id.rs");
    let mut f = File::create(&dest_path).unwrap();

    f.write_all(b"pub const BUILD_ID : &'static str = \"").unwrap();
    f.write_all(gitver.as_bytes()).unwrap();
    f.write_all(b"\";\n").unwrap();
}

