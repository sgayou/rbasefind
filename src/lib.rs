extern crate byteorder;
extern crate clap;
extern crate fnv;
extern crate num_cpus;
extern crate regex;

use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use clap::App;
use fnv::FnvHashSet;
use regex::bytes::Regex;
use std::error::Error;
use std::fs::File;
use std::io::Cursor;
use std::io::prelude::*;
use std::sync::Arc;
use std::thread;

pub struct Config {
    big_endian: bool,
    filename: String,
    min_str_len: u32,
    offset: u32,
    threads: usize,
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
                -o, --offset=[LEN]      'Scan every N addresses. (default is 0x1000)'
                -t  --threads=[NUM_THREADS] '# of threads to spawn. (default is # of cpu cores)'",
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
            threads: match arg_matches.value_of("threads").unwrap_or("0").parse() {
                Ok(v) => if v == 0 {
                    num_cpus::get()
                } else {
                    v
                },
                Err(_) => return Err("failed to parse threads"),
            },
        };

        Ok(config)
    }
}

fn get_strings(config: &Config, buffer: &[u8]) -> Result<FnvHashSet<u32>, Box<Error>> {
    let mut strings = FnvHashSet::default();

    let reg_str = format!("[ -~\\t\\r\\n]{{{},}}\x00", config.min_str_len);
    for mat in Regex::new(&reg_str)?.find_iter(&buffer[..]) {
        strings.insert(mat.start() as u32);
    }

    Ok(strings)
}

fn get_pointers(config: &Config, buffer: &[u8]) -> Result<FnvHashSet<u32>, Box<Error>> {
    let mut pointers = FnvHashSet::default();
    let mut rdr = Cursor::new(&buffer);
    loop {
        let res = if config.big_endian {
            rdr.read_u32::<BigEndian>()
        } else {
            rdr.read_u32::<LittleEndian>()
        };
        match res {
            Ok(v) => pointers.insert(v),
            Err(_) => break,
        };
    }

    Ok(pointers)
}

fn get_interval(interval: usize, max_threads: usize) -> (u32, u32) {
    let start_addr =
        (interval * ((u32::max_value() as usize + max_threads - 1) / max_threads)) as u32;
    let mut end_addr =
        ((interval + 1) * ((u32::max_value() as usize + max_threads - 1) / max_threads)) as u32;
    if end_addr == 0 {
        end_addr = u32::max_value();
    }

    (start_addr, end_addr)
}

fn find_matches(
    config: &Config,
    strings: &FnvHashSet<u32>,
    pointers: &FnvHashSet<u32>,
    scan_interval: usize,
) -> Result<(), Box<Error>> {
    let mut most_intersections = 0;
    let (mut current_addr, end_addr) = get_interval(scan_interval, config.threads);

    while current_addr <= end_addr {
        let mut news = FnvHashSet::default();
        for s in strings {
            match s.checked_add(current_addr) {
                Some(add) => news.insert(add),
                None => continue,
            };
        }
        let intersection: FnvHashSet<_> = news.intersection(pointers).collect();
        if intersection.len() > most_intersections {
            most_intersections = intersection.len();
            println!(
                "Matched {} strings to pointers at 0x{:08x}",
                intersection.len(),
                current_addr
            );
        }
        match current_addr.checked_add(config.offset) {
            Some(_) => current_addr += config.offset,
            None => break,
        };
    }

    Ok(())
}

pub fn run(config: Config) -> Result<(), Box<Error>> {
    // Read in the input file. We jam it all into memory for now.
    let mut f = File::open(&config.filename)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;

    // Find indices of strings.
    let strings = get_strings(&config, &buffer)?;

    if strings.is_empty() {
        return Err("No strings found in target binary".into());
    }
    eprintln!("Located {} strings", strings.len());

    let pointers = get_pointers(&config, &buffer)?;
    eprintln!("Located {} pointers", pointers.len());

    // Make a vector to hold the children which are spawned.
    let mut children = vec![];
    let shared_config = Arc::new(config);
    let shared_strings = Arc::new(strings);
    let shared_pointers = Arc::new(pointers);

    for i in 0..shared_config.threads {
        // Spin up another thread
        let child_config = Arc::clone(&shared_config);
        let child_strings = Arc::clone(&shared_strings);
        let child_pointers = Arc::clone(&shared_pointers);
        children.push(thread::spawn(move || {
            if let Err(e) = find_matches(&child_config, &child_strings, &child_pointers, i) {
                eprintln!("Thread error: {}", e);
            }
        }));
    }

    for child in children {
        let _ = child.join();
    }

    Ok(())
}
