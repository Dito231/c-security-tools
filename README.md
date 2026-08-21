# C Security Tools

Low-level security utilities written in C. Built for learning systems programming concepts that matter in security work — file I/O, memory layout, process internals, and log parsing.

**Author:** Gabriel Lopez ([@Dito231](https://github.com/Dito231))

## Tools

### hex-viewer
Interactive hex dump viewer for binary analysis. Displays files in canonical hex+ASCII format (similar to `xxd`), with colorized output highlighting printable vs. non-printable bytes. Supports offset navigation and search.

```bash
cd hex-viewer && make
./hexview firmware.bin              # Full dump
./hexview -o 0x200 -n 512 malware.exe  # 512 bytes starting at offset 0x200
./hexview -s "MZ" malware.exe       # Search for pattern
```

### log-parser
Structured log parser that reads auth.log, syslog, or custom formats and extracts fields (timestamp, source, severity, message). Outputs filtered results as plain text or CSV for pipeline integration.

```bash
cd log-parser && make
./logparse /var/log/auth.log                     # Parse full log
./logparse -f "Failed password" /var/log/auth.log # Filter by pattern
./logparse -c -f "sshd" /var/log/auth.log        # CSV output, filter by sshd
```

### process-enumerator
Lists running processes by reading `/proc` on Linux. Displays PID, PPID, user, command line, memory usage, and open file descriptors. Useful for quick triage of a live system without installing tools.

```bash
cd process-enumerator && make
./procenum                  # List all processes
./procenum -u root          # Filter by user
./procenum -p 1234          # Details for specific PID
./procenum -f               # Show open file descriptors
```

## Building

Each tool has its own Makefile. Requires GCC and standard POSIX headers (Linux).

```bash
# Build all
for dir in hex-viewer log-parser process-enumerator; do
    (cd $dir && make)
done

# Clean all
for dir in hex-viewer log-parser process-enumerator; do
    (cd $dir && make clean)
done
```

## Why C?

These tools exist at a level of abstraction that matters for security:
- **hex-viewer** — understanding file formats, PE headers, and magic bytes is foundational for malware analysis
- **log-parser** — parsing structured text at speed is what SIEMs do; building one from scratch teaches you what fields matter
- **process-enumerator** — `/proc` is how EDR agents and rootkit detectors see the system; knowing what's there helps you spot what's hidden

## License

MIT
