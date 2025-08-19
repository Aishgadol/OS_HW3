# Encdec Linux Kernel Module

## Project Description
This repository contains a Linux kernel module named `encdec` that exposes two
character devices implementing simple encryption and decryption mechanisms. The
module supports Caesar cipher and XOR cipher operations and can be controlled via
custom ioctl commands. A user‑space test program (`test.c`) and shell scripts for
loading and unloading the module are provided.

## Goals & Objectives
- Provide a minimal kernel module for educational purposes demonstrating
  character device registration, memory management and ioctl handling.
- Support two encryption modes: Caesar and XOR, each mapped to separate device
  minors (`/dev/encdec0` and `/dev/encdec1`).
- Allow users to set the key, zero device buffers and configure read behaviour
  (raw or decrypted).
- Supply example tests to verify functionality.

## Architecture & Components
- **encdec.c / encdec.h** – Implementation and interface of the kernel module.
  Defines ioctls `ENCDEC_CMD_CHANGE_KEY`, `ENCDEC_CMD_SET_READ_STATE` and
  `ENCDEC_CMD_ZERO`, and implements read/write handlers for each encryption mode.
- **Makefile** – Compiles `encdec.o` against a specified kernel tree. Adjust the
  `KERNELDIR` variable to match your system headers.
- **load / unload** – Shell scripts that insert or remove the module and create
  `/dev/encdec0` and `/dev/encdec1` device nodes.
- **test.c** – Interactive user‑space program exercising the module via open,
  read/write, lseek and ioctl calls. Predefined command scripts (`test1.in`,
  `test2.in`, …) demonstrate typical usage.
- **test** – Prebuilt binary of `test.c` (included for reference).
- **hw3.pdf** – Assignment or design document for the project.

## Installation & Prerequisites
1. Ensure you have kernel headers and build tools installed. Update the
   `KERNELDIR` path inside `Makefile` if necessary.
2. Compile the module, the interactive test program and the simple reader:
   ```bash
   make            # builds encdec.o
   gcc test.c -o test
   gcc reader.c -o reader
   ```
3. (Optional) Set executable permission on helper scripts:
   ```bash
   chmod +x load unload
   ```
4. Load the module with a memory buffer size (default 50 bytes if omitted):
   ```bash
   sudo ./load 100
   ```

## Usage & Examples
Run the interactive tester and feed it a script:
```bash
./test < test1.in
```
Common commands within the tester include:
- `open <device> <fd_index> <mode>` – open `/dev/encdec0` or `/dev/encdec1` with
  read, write or read|write permissions.
- `ioctl <fd_index> change_key <value>` – set encryption key.
- `ioctl <fd_index> change_read_state <raw|decrypt>` – choose whether reads
  return raw bytes or decrypted text.
- `write <fd_index> "text"` and `read <fd_index> <count>` – perform I/O.
- `lseek <fd_index> <pos>` – set the file position.

### Simple Reader Utility
An additional example program `reader.c` is provided for quickly reading data
from one of the encdec devices without using the interactive tester. Compile it
with:
```bash
gcc reader.c -o reader
```
Example usage reading 20 decrypted bytes from `/dev/encdec0` using key `4`:
```bash
./reader /dev/encdec0 20 --key 4 --decrypt
```
It supports the `--raw` flag to read encrypted bytes instead.

To unload the module and clean device nodes:
```bash
sudo ./unload
```

## Expected Results & Outputs
Running the tests generates success or error messages printed to stdout. The
module itself does not store persistent files; it keeps data in kernel memory
until the module is removed or buffers are zeroed via ioctl. The tester scripts
illustrate correct encryption/decryption behaviour and boundary conditions.

## Development & Contribution
- Edit the C source following the kernel coding style.
- Recompile with `make` after changes. To run the test suite, simply execute the
  provided command scripts through `./test`. Additional tests can be created in
  the same format as `test1.in`.
- Pull requests are welcome. Please base work on the latest main branch and
  include clear commit messages.

## Project Status & Roadmap
This code represents a course assignment and should be considered **alpha**
quality. Possible improvements include enhanced error handling, support for
larger buffers, and cleanup of the Makefile for modern kernels.

## License & Attribution
The kernel module declares `MODULE_LICENSE("GPL")`. If redistributing, apply a
GPLv2 compatible license and retain authorship credits contained in the source
(`Idan Morad, Or Dinar`).

