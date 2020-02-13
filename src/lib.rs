extern crate byteorder;
extern crate clap;
extern crate fnv;
extern crate num_cpus;
extern crate regex;
extern crate pbr;

use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use clap::App;
use fnv::FnvHashSet;
use regex::bytes::Regex;
use std::collections::BinaryHeap;
use std::error::Error;
use std::fs::File;
use std::io::Cursor;
use std::io::prelude::*;
use std::sync::Arc;
use std::thread;
use pbr::MultiBar;

pub struct Config {
    big_endian: bool,
    filename: String,
    min_str_len: usize,
    max_matches: usize,
    offset: u32,
    threads: usize,
}

impl Config {
    pub fn new() -> Result<Config, &'static str> {
        let arg_matches = App::new("rbasefind")
            .version("0.1.2")
            .author("Scott G. <github.scott@gmail.com>")
            .about(
                "Scan a flat 32-bit binary and attempt to brute-force the base address via \
                 string/pointer comparison. Based on the excellent basefind.py by mncoppola.",
            )
            .args_from_usage(
                "<INPUT>                'The input binary to scan'
                -b, --bigendian         'Interpret as Big Endian (default is little)'
                -m, --minstrlen=[LEN]   'Minimum string search length (default is 10)'
                -n, --maxmatches=[LEN]   'Maximum matches to display (default is 10)'
                -o, --offset=[LEN]      'Scan every N (power of 2) addresses. (default is 0x1000)'
                -t  --threads=[NUM_THREADS] '# of threads to spawn. (default is # of cpu cores)'",
            )
            .get_matches();

        let config = Config {
            big_endian: arg_matches.is_present("bigendian"),
            filename: arg_matches.value_of("INPUT").unwrap().to_string(),
            max_matches: match arg_matches.value_of("maxmatches").unwrap_or("10").parse() {
                Ok(v) => v,
                Err(_) => return Err("failed to parse maxmatches"),
            },
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
                // This check also prevents offset_num from being zero.
                if offset_num.count_ones() != 1 {
                    return Err("Offset is not a power of 2");
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

pub struct Interval {
    start_addr: u32,
    end_addr: u32,
}

impl Interval {
    fn get_range(
        index: usize,
        max_threads: usize,
        offset: u32,
    ) -> Result<Interval, Box<dyn Error + Send + Sync>> {
        if index >= max_threads {
            return Err("Invalid index specified".into());
        }

        if offset.count_ones() != 1 {
            return Err("Invalid additive offset".into());
        }

        let mut start_addr = index as u64
            * ((u64::from(u32::max_value()) + max_threads as u64 - 1) / max_threads as u64);
        let mut end_addr = (index as u64 + 1)
            * ((u64::from(u32::max_value()) + max_threads as u64 - 1) / max_threads as u64);

        // Mask the address such that it's aligned to the 2^N offset.
        start_addr &= !(u64::from(offset) - 1);
        if end_addr >= u64::from(u32::max_value()) {
            end_addr = u64::from(u32::max_value());
        } else {
            end_addr &= !(u64::from(offset) - 1);
        }

        let interval = Interval {
            start_addr: start_addr as u32,
            end_addr: end_addr as u32,
        };

        Ok(interval)
    }
}

fn get_strings(config: &Config, buffer: &[u8]) -> Result<FnvHashSet<u32>, Box<dyn Error>> {
    let mut strings = FnvHashSet::default();

    let reg_str = format!("[ -~\\t\\r\\n]{{{},}}\x00", config.min_str_len);
    for mat in Regex::new(&reg_str)?.find_iter(&buffer[..]) {
        strings.insert(mat.start() as u32);
    }

    Ok(strings)
}

fn get_pointers(config: &Config, buffer: &[u8]) -> Result<FnvHashSet<u32>, Box<dyn Error>> {
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

fn find_matches(
    config: &Config,
    strings: &FnvHashSet<u32>,
    pointers: &FnvHashSet<u32>,
    scan_interval: usize,
    mut pb: pbr::ProgressBar<pbr::Pipe>,
) -> Result<BinaryHeap<(usize, u32)>, Box<dyn Error + Send + Sync>> {
    let interval = Interval::get_range(scan_interval, config.threads, config.offset)?;
    let mut current_addr = interval.start_addr;
    let mut heap = BinaryHeap::<(usize, u32)>::new();
    pb.total = ((interval.end_addr - interval.start_addr)/config.offset) as u64;
    while current_addr <= interval.end_addr {
        let mut news = FnvHashSet::default();
        for s in strings {
            match s.checked_add(current_addr) {
                Some(add) => news.insert(add),
                None => continue,
            };
        }
        let intersection: FnvHashSet<_> = news.intersection(pointers).collect();
        if !intersection.is_empty() {
            heap.push((intersection.len(), current_addr));
        }
        match current_addr.checked_add(config.offset) {
            Some(_) => current_addr += config.offset,
            None => break,
        };
        pb.inc();
    }
    pb.finish();

    Ok(heap)
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
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

    let mut children = vec![];
    let shared_config = Arc::new(config);
    let shared_strings = Arc::new(strings);
    let shared_pointers = Arc::new(pointers);


    let mut mb = MultiBar::new();
    mb.println(&format!("Scanning with {} threads...", shared_config.threads));
    for i in 0..shared_config.threads {
        let mut pb = mb.create_bar(100);
        pb.show_message = true;
        let child_config = Arc::clone(&shared_config);
        let child_strings = Arc::clone(&shared_strings);
        let child_pointers = Arc::clone(&shared_pointers);
        children.push(thread::spawn(move || {
            find_matches(&child_config, &child_strings, &child_pointers, i, pb)
        }));
    }

    mb.listen();

    // Merge all of the heaps.
    let mut heap = BinaryHeap::<(usize, u32)>::new();
    for child in children {
        heap.append(&mut child.join().unwrap().unwrap());
    }

    // Print (up to) top N results.
    for _ in 0..shared_config.max_matches {
        let (count, addr) = match heap.pop() {
            Some(v) => v,
            None => break,
        };
        println!("0x{:08x}: {}", addr, count);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn find_matches_invalid_interval() {
        let _ = Interval::get_range(1, 1, 0x1000).unwrap();
    }

    #[test]
    fn find_matches_single_cpu_interval_0() {
        let interval = Interval::get_range(0, 1, 0x1000).unwrap();
        assert_eq!(interval.start_addr, u32::min_value());
        assert_eq!(interval.end_addr, u32::max_value());
    }

    #[test]
    fn find_matches_double_cpu_interval_0() {
        let interval = Interval::get_range(0, 2, 0x1000).unwrap();
        assert_eq!(interval.start_addr, u32::min_value());
        assert_eq!(interval.end_addr, 0x80000000);
    }

    #[test]
    fn find_matches_double_cpu_interval_1() {
        let interval = Interval::get_range(1, 2, 0x1000).unwrap();
        assert_eq!(interval.start_addr, 0x80000000);
        assert_eq!(interval.end_addr, u32::max_value());
    }

    #[test]
    fn find_matches_triple_cpu_interval_0() {
        let interval = Interval::get_range(0, 3, 0x1000).unwrap();
        assert_eq!(interval.start_addr, u32::min_value());
        assert_eq!(interval.end_addr, 0x55555000);
    }

    #[test]
    fn find_matches_triple_cpu_interval_1() {
        let interval = Interval::get_range(1, 3, 0x1000).unwrap();
        assert_eq!(interval.start_addr, 0x55555000);
        assert_eq!(interval.end_addr, 0xAAAAA000);
    }

    #[test]
    fn find_matches_triple_cpu_interval_2() {
        let interval = Interval::get_range(2, 3, 0x1000).unwrap();
        assert_eq!(interval.start_addr, 0xAAAAA000);
        assert_eq!(interval.end_addr, u32::max_value());
    }
}
