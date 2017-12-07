extern crate byteorder;
extern crate clap;
extern crate fnv;
extern crate rbasefind;
extern crate regex;

use rbasefind::Config;
use std::process;

fn main() {
    let config = Config::new().unwrap_or_else(|err| {
        eprintln!("Problem parsing arguments: {}", err);
        process::exit(1);
    });

    if let Err(e) = rbasefind::run(&config) {
        eprintln!("Application error: {}", e);
        process::exit(1);
    }
}