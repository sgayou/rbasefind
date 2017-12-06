extern crate byteorder;
extern crate clap;
extern crate fnv;
extern crate regex;

use byteorder::{ReadBytesExt, LittleEndian, BigEndian};
use clap::App;
use fnv::FnvHashSet;
use regex::bytes::Regex;
use std::error::Error;
use std::fs::File;
use std::io::Cursor;
use std::io::prelude::*;

pub struct Config {
    big_endian: bool,
    filename: String,
    min_str_len: u32,
    offset: u32,
}

impl Config {
    pub fn new() -> Result<Config, &'static str> {
        let arg_matches = App::new("rbasefind")
            .version("0.1.0")
            .author("Scott G. <github.scott@gmail.com>")
            .about(
                "Scan a flat 32-bit binary and attempt to brute-force the base address via \
                string/pointer comparison. Based on the excellent basefind.py by mncoppola.",
            )
            .args_from_usage(
                "<INPUT>                'The input binary to scan'
                            -b, --bigendian         'Interpret as Big Endian (default is little)'
                            -m, --minstrlen=[LEN]   'Minimum string search length (default is 10)'
                            -o, --offset=[LEN]      'Scan every N addresses. (default is 0x1000)'",
            )
            .get_matches();

        let config = Config {
            big_endian: arg_matches.is_present("bigendian"),
            filename: arg_matches.value_of("INPUT").unwrap().to_string(),
            min_str_len: match arg_matches.value_of("minstrlen").unwrap_or("10").parse() {
                Ok(v) => v,
                Err(_) => return Err("failed to parse minstrlen"),
            },
            offset: {
                let offset_str = &arg_matches.value_of("offset").unwrap_or("0x1000");
                if offset_str.len() <= 2 {
                    return Err("offset format is invalid");
                }
                if &offset_str[0..2] != "0x" {
                    return Err("ensure offset parameter begins with 0x.");
                }
                let offset_num = match u32::from_str_radix(&offset_str[2..], 16) {
                    Ok(v) => v,
                    Err(_) => return Err("failed to parse offset"),
                };
                if offset_num == 0 {
                    return Err("0 offset is invalid");
                }
                offset_num
            },
        };

        Ok(config)
    }
}


pub fn run(config: Config) -> Result<(), Box<Error>> {
    // Read in the input file. We jam it all into memory for now.
    let mut f = File::open(config.filename)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;

    // Find indices of strings.
    let mut strings = FnvHashSet::default();
    // Scan for printable ascii characters as well as tab, carriage return, and newline before null.
    let reg_str = format!("[ -~\\t\\r\\n]{{{},}}\x00", config.min_str_len);
    for mat in Regex::new(&reg_str)?.find_iter(&buffer[..]) {
        strings.insert(mat.start() as u32);
    }

    if strings.len() == 0 {
        return Err("No strings found in target binary".into());
    }
    eprintln!("Located {} strings", strings.len());

    // Simply assume every 32-bit value is a pointer. Naïve!
    let mut pointers = FnvHashSet::default();
    let mut rdr = Cursor::new(&buffer);
    loop {
        if config.big_endian {
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
    eprintln!("Located {} pointers", pointers.len());

    // Look for a match.
    let mut most_intersections = 0;
    let mut addr: u32 = u32::min_value();
    eprintln!(
        "Starting scan at 0x{:X} with 0x{:x} byte interval",
        u32::min_value(),
        config.offset
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
                "Matched {} strings to pointers at 0x{:x}",
                intersection.len(),
                addr
            );
        }
        match addr.checked_add(config.offset) {
            Some(_) => addr += config.offset,
            None => break,
        };
    }

    Ok(())
}
