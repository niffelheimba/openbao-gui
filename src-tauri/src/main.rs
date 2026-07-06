#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    openbao_certificate_client::run();
}
