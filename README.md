# rbasefind
A brute-force base address scanner based on [@mncoppola's](https://github.com/mncoppola) [basefind.py](https://github.com/mncoppola/ws30/blob/master/basefind.py) & [@rsaxvc's](https://github.com/rsaxvc) [basefind.cpp](https://github.com/mncoppola/ws30/blob/master/basefind.cpp) implemented in rust.

## Features
Scans a flat, 32-bit binary file and attempts to calculate the base address of the image. Looks for ASCII English strings then finds the greatest intersection of all 32-bit words interpreted as pointers and the offsets of the strings.

This works rather well on some ARM (non-thumb) binaries. It's a very simple heuristic that attempts to use as little information about the file as possible from the target binary. As such, it isn't going to work miracles.

### Example
Below we scan a little-endian firmware image and set the minimum string length to 100. Lower minimum string lengths may give more accurate results but take more time. -m 100 returns almost instantly.
```bash
$ ./rbasefind fw_all.bin 
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
```
0x2000 was the correct base address for this binary.

## TODO
* Some form of auto mode. Detect endianness based on highest intersection. Auto decrease offset in window around highest match.
