// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(windows)]
fn print_link_search_path() {
    use std::env;

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    if cfg!(target_arch = "x86_64") {
        println!("cargo:rustc-link-search=native={}/lib/x64", manifest_dir);
    } else {
        println!("cargo:rustc-link-search=native={}/lib", manifest_dir);
    }
}

#[cfg(not(windows))]
fn print_link_search_path() {}

fn main() {
    // `pnettest` holds live-network integration tests that require elevated
    // privileges and real interfaces; gate them behind an opt-in custom cfg.
    // Declare it so `unexpected_cfgs` doesn't flag the `#[cfg(pnet_test_network)]`.
    println!("cargo::rustc-check-cfg=cfg(pnet_test_network)");
    print_link_search_path();
}
