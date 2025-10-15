# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ngrep is a network packet analyzer that applies regular expressions to network traffic. It's essentially "grep for network packets" - a PCAP-based tool for matching data payloads against regular expressions or hexadecimal patterns across various network protocols (IPv4/6, TCP, UDP, ICMP, etc.).

## Architecture

- **Single-file C application**: Primary logic in `ngrep.c` (~42k lines)
- **Header file**: `ngrep.h` defines constants, structures, and function prototypes
- **Autotools build system**: Uses autoconf/automake with `configure.in` and `Makefile.in`
- **Embedded regex library**: Ships with GNU regex library in `regex-0.12/` as fallback
- **Optional tcpkill functionality**: `tcpkill.c/h` for connection termination (requires libnet)
- **Platform abstraction**: Extensive platform-specific code for Linux, BSD, Solaris, Windows, etc.

The application follows a classic packet capture workflow:
1. Initialize libpcap and setup BPF filters
2. Setup regex/hex pattern matching
3. Process packets in callback function (`process()`)
4. Apply filters and display matches

## Build Commands

### Standard Unix Build
```bash
./configure && make
```

### Debug Build
```bash
./configure && make debug
```

### Static Binary
```bash
./configure && make static
```

### Multi-architecture Docker Build
```bash
./docker-build.sh
```
This creates static binaries for AMD64 and ARM64 in the `bin/` directory.

**IMPORTANT: Always test builds using `./docker-build.sh`** - This is the primary testing method as it ensures the code compiles in a clean Alpine environment with proper static linking. The Docker build provides the most reliable compilation test.

### Clean
```bash
make clean      # Clean build artifacts
make distclean  # Also remove autoconf-generated files
```

## Configuration Options

Key `./configure` options:
- `--enable-ipv6`: Enable IPv6 support
- `--enable-pcre`: Use PCRE instead of GNU regex
- `--enable-tcpkill`: Enable connection killing (requires libnet)
- `--disable-dropprivs`: Disable privilege dropping
- `--with-pcap-includes=DIR`: Specify pcap header location
- `--enable-pcap-restart`: Fix for older libpcap versions

## Code Structure

- **Packet processing**: `process()` function handles all captured packets
- **Output formatting**: Multiple dump functions (`dump_packet`, `dump_formatted`, `dump_byline`)
- **Pattern matching**: Pluggable match functions (`re_match_func`, `bin_match_func`, etc.)
- **Platform handling**: Extensive OS-specific ifdefs for compatibility
- **BPF filter logic**: Smart handling of user-specified vs. auto-generated filters
- **VLAN support**: Automatic inclusion of VLAN frames in IP filters

## Development Notes

- The codebase prioritizes broad platform compatibility over modern C practices
- Heavy use of preprocessor macros for cross-platform support  
- BPF filter handling includes complex logic for backward compatibility
- Packet decoder handles variable frame offsets (especially for VLAN)
- Memory management is manual throughout
- No formal test suite - testing typically done manually with live traffic

## Key Files

- `ngrep.c`: Main application logic
- `ngrep.h`: Header with constants and prototypes  
- `configure.in`: Autoconf configuration
- `Makefile.in`: Build template
- `ngrep.8`: Man page
- `docker-build.sh`: Multi-arch build script
- `Dockerfile`: Alpine-based build environment
- `regex-0.12/`: Embedded GNU regex library
- `tcpkill.c/h`: Optional connection termination feature