use embed_manifest::{embed_manifest, new_manifest};

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest(new_manifest("Azazel.CoE5Assistant"))
            .expect("unable to embed Windows application manifest");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
