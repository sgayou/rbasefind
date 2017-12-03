# rbasefind
A rust brute-force base address scanner based on [@mncoppola's](https://github.com/mncoppola) excellent [basefind.py](https://github.com/mncoppola/ws30/blob/master/basefind.py). Dramatically faster.

## Features
Scans a flat, 32-bit binary file and attempts to calculate the base address of the image. Looks for ASCII English strings then finds the greatest intersection of all 32-bit words interpreted as pointers and the offsets of the strings.

This works rather well on some ARM (non-thumb) binaries. It's a very simple heuristic that attempts to use as little information about the file as possible from the target binary. As such, it isn't going to work miracles.

### Example
Below we scan a little-endian firmware image and set the minimum string length to 100. Lower minimum string lengths may give more accurate results but take more time. -m 100 returns almost instantly.
```bash
./rbasefind fw_img.bin -m 100
Located 38 strings.
Located 540091 pointers.
Starting scan at 0x0 with 0x1000 byte interval.
Matched 5 strings to pointers at 0x0.
Matched 38 strings to pointers at 0x2000.
```
0x2000 was the correct base address for this binary.

## TODO
* Store top matches in a heap then print them at the end.
* Some form of progress indication.
* Multithreading.
* Check if thumb works the same way. 16-bit mode?
