# rbasefind
A brute-force base address scanner based on [@mncoppola's](https://github.com/mncoppola) [basefind.py](https://github.com/mncoppola/ws30/blob/master/basefind.py) & [@rsaxvc's](https://github.com/rsaxvc) [basefind.cpp](https://github.com/mncoppola/ws30/blob/master/basefind.cpp) implemented in rust.

## Features
Scans a flat, 32-bit binary file and attempts to calculate the base address of the image. Looks for ASCII English strings then finds the greatest intersection of all 32-bit words interpreted as pointers and the offsets of the strings.

This works rather well on some ARM (non-thumb) binaries. It's a very simple heuristic that attempts to use as little information about the file as possible from the target binary. As such, it isn't going to work miracles.

### Help
```
Scan a flat 32-bit binary and attempt to brute-force the base address via string/pointer comparison. Based on the
excellent basefind.py by mncoppola.

USAGE:
    rbasefind [FLAGS] [OPTIONS] <INPUT>

FLAGS:
    -b, --bigendian    Interpret as big-endian (default is little)
    -h, --help         Prints help information
    -p, --progress     Show progress
    -V, --version      Prints version information

OPTIONS:
    -n, --maxmatches <LEN>         Maximum matches to display (default is 10)
    -m, --minstrlen <LEN>          Minimum string search length (default is 10)
    -o, --offset <LEN>             Scan every N (power of 2) addresses. (default is 0x1000)
    -t, --threads <NUM_THREADS>    # of threads to spawn. (default is # of cpu cores)

ARGS:
    <INPUT>    The input binary to scan
```

### Example

```bash
time ./rbasefind fw.bin 
Located 2355 strings
Located 372822 pointers
Scanning with 8 threads...
0x00002000: 2195
0x00001000: 103
0x00000000: 102
0x00003000: 101
0x00004000: 90
0x45e95000: 74
0x45e93000: 73
0x00006000: 64
0x00005000: 59
0x45ec3000: 58

real	0m40.937s
user	5m20.908s
sys	0m0.035s
```

`0x00002000` was the correct base address for this binary.

For large binaries, the default scan may take too long. The search size can be dialed down, at the expense of "accuracy", via specifying a minimum string length. i.e.,

```
time ./target/release/rbasefind fw_all.bin -m 100
Located 7 strings
Located 372822 pointers
Scanning with 8 threads...
0x00002000: 4
0x2ae7b000: 2
0xffe54000: 1
0xfba46000: 1
0xfb9c3000: 1
0xfb80a000: 1
0xfafe6000: 1
0xfafe0000: 1
0xfae3b000: 1
0xfae13000: 1

real	0m0.149s
user	0m0.751s
sys	0m0.012s
```

## TODO
* Some form of auto mode. Detect endianness based on highest intersection. Auto decrease offset in window around highest match.
