extern crate byteorder;
extern crate clap;
extern crate fnv;
extern crate regex;

use byteorder::{ReadBytesExt, LittleEndian, BigEndian};
use clap::App;
use fnv::FnvHashSet;
use regex::bytes::Regex;
use std::fs::File;
use std::io::Cursor;
use std::io::prelude::*;
use std::process;

const SCAN_OFFSET: u32 = 0x1000;

fn main() {
    let matches = App::new("rbasefind")
        .version("0.1.0")
        .author("Scott G. <github.scott@gmail.com>")
        .about(
            "Scan a flat 32-bit binary and attempt to brute-force the base address via \
             string/pointer comparison. Based on the excellent basefind.py by mncoppola \
             but dramatically faster.",
        )
        .args_from_usage(
            "<INPUT>                'The input binary to scan'
                         -b, --bigendian         'Interpret as Big Endian (default is little)'
                         -m, --minstrlen=[LEN]   'Minimum string search length (default is 10)'",
        )
        .get_matches();

    let filename = matches.value_of("INPUT").unwrap();
    let min_str_len = match matches.value_of("minstrlen").unwrap_or("10").parse::<i32>() {
        Ok(num) => num,
        Err(_) => {
            eprintln!("Failed to parse minstrlen parameter.");
            process::exit(1);
        }
    };

    let big_endian = matches.is_present("bigendian");

    // Read in the input file. We jam it all into memory for now.
    let mut f = File::open(filename).expect("file not found");
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).expect("failed to read file");

    // Find indices of strings.
    let mut strings = FnvHashSet::default();
    // Scan for printable ascii characters as well as tab, carriage return, and newline before null.
    let reg_str = format!("[ -~\\t\\r\\n]{{{},}}\x00", min_str_len);
    for mat in Regex::new(&reg_str).unwrap().find_iter(&buffer[..]) {
        strings.insert(mat.start() as u32);
    }
    eprintln!("Located {} strings.", strings.len());

    // Simply assume every 32-bit value is a pointer. Naïve!
    let mut pointers = FnvHashSet::default();
    let mut rdr = Cursor::new(&buffer);
    loop {
        if big_endian {
            match rdr.read_u32::<BigEndian>() {
                Ok(v) => pointers.insert(v),
                Err(_) => break,
            };
        } else {
            match rdr.read_u32::<LittleEndian>() {
                Ok(v) => pointers.insert(v),
                Err(_) => break,
            };
        }
    }

    eprintln!("Located {} pointers.", pointers.len());

    // Look for a match.
    let mut most_intersections = 0;
    let mut addr: u32 = u32::min_value();
    eprintln!(
        "Starting scan at 0x{:X} with 0x{:x} byte interval.",
        u32::min_value(),
        SCAN_OFFSET
    );
    while addr < u32::max_value() {
        let mut news = FnvHashSet::default();
        for s in &strings {
            match s.checked_add(addr) {
                Some(add) => news.insert(add),
                None => continue,
            };
        }
        let intersection: FnvHashSet<_> = news.intersection(&pointers).collect();
        if intersection.len() > most_intersections {
            most_intersections = intersection.len();
            println!(
                "Matched {} strings to pointers at 0x{:x}.",
                intersection.len(),
                addr
            );
        }
        match addr.checked_add(SCAN_OFFSET) {
            Some(_) => addr += SCAN_OFFSET,
            None => break,
        };
    }
}
