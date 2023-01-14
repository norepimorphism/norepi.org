// SPDX-License-Identifier: MPL-2.0

fn main() {
    let dir = format!("{}/gen", std::env::var("OUT_DIR").unwrap());
    let _ = std::fs::create_dir_all(&dir);
    std::env::set_current_dir(&dir).expect("failed to change directory");

    generate_norepi_site::run();
}
