---
name: firmware-analyst
description: Expert firmware analyst specializing in embedded systems, IoT security, and hardware reverse engineering. Masters firmware extraction, analysis, and vulnerability research for routers, IoT devices, au
category: Security & Systems
source: antigravity
tags: [markdown, api, ai, workflow, template, document, image, security, vulnerability, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/firmware-analyst
---


# Download from vendor
wget http://vendor.com/firmware/update.bin

# Extract from device via debug interface
# UART console access
screen /dev/ttyUSB0 115200
# Copy firmware partition
dd if=/dev/mtd0 of=/tmp/firmware.bin

# Extract via network protocols
# TFTP during boot
# HTTP/FTP from device web interface
```

### Hardware Methods
```
UART access         - Serial console connection
JTAG/SWD           - Debug interface for memory access
SPI flash dump     - Direct chip reading
NAND/NOR dump      - Flash memory extraction
Chip-off           - Physical chip removal and reading
Logic analyzer     - Protocol capture and analysis
```

## Use this skill when

- Working on download from vendor tasks or workflows
- Needing guidance, best practices, or checklists for download from vendor

## Do not use this skill when

- The task is unrelated to download from vendor
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Firmware Analysis Workflow

### Phase 1: Identification
```bash
# Basic file identification
file firmware.bin
binwalk firmware.bin

# Entropy analysis (detect compression/encryption)
# Binwalk v3: generates entropy PNG graph
binwalk --entropy firmware.bin
binwalk -E firmware.bin  # Short form

# Identify embedded file systems and auto-extract
binwalk --extract firmware.bin
binwalk -e firmware.bin  # Short form

# String analysis
strings -a firmware.bin | grep -i "password\|key\|secret"
```

### Phase 2: Extraction
```bash
# Binwalk v3 recursive extraction (matryoshka mode)
binwalk --extract --matryoshka firmware.bin
binwalk -eM firmware.bin  # Short form

# Extract to custom directory
binwalk -e -C ./extracted firmware.bin

# Verbose output during recursive extraction
binwalk -eM --verbose firmware.bin

# Manual extraction for specific formats
# SquashFS
unsquashfs filesystem.squashfs

# JFFS2
jefferson filesystem.jffs2 -d output/

# UBIFS
ubireader_extract_images firmware.ubi

# YAFFS
unyaffs filesystem.yaffs

# Cramfs
cramfsck -x output/ filesystem.cramfs
```

### Phase 3: File System Analysis
```bash
# Explore extracted filesystem
find . -name "*.conf" -o -name "*.cfg"
find . -name "passwd" -o -name "shadow"
find . -type f -executable

# Find hardcoded credentials
grep -r "password" .
grep -r "api_key" .
grep -rn "BEGIN RSA PRIVATE KEY" .

# Analyze web interface
find . -name "*.cgi" -o -name "*.php" -o -name "*.lua"

# Check for vulnerable binaries
checksec --dir=./bin/
```

### Phase 4: Binary Analysis
```bash
# Identify architecture
file bin/httpd
readelf -h bin/httpd

# Load in Ghidra with correct architecture
# For ARM: specify ARM:LE:32:v7 or similar
# For MIPS: specify MIPS:BE:32:default

# Set up cross-compilation for testing
# ARM
arm-linux-gnueabi-gcc exploit.c -o exploit
# MIPS
mipsel-linux-gnu-gcc exploit.c -o exploit
```

## Common Vulnerability Classes

### Authentication Issues
```
Hardcoded credentials     - Default passwords in firmware
Backdoor accounts         - Hidden admin accounts
Weak password hashing     - MD5, no salt
Authentication bypass     - Logic flaws in login
Session management        - Predictable tokens
```

### Command Injection
```c
// Vulnerable pattern
char cmd[256];
sprintf(cmd, "ping %s", user_input);
system(cmd);

// Test payloads
; id
| cat /etc/passwd
`whoami`
$(id)
```

### Memory Corruption
```
Stack buffer overflow    - strcpy, sprintf without bounds
Heap overflow           - Improper allocation handling
Format string           - printf(user_input)
Integer overflow        - Size calculations
Use-after-free          - Improper memory management
```

### Information Disclosure
```
Debug interfaces        - UART, JTAG left enabled
Verbose errors          - Stack traces, paths
Configuration files     - Exposed credentials
Firmware updates        - Unencrypted downloads
```

## Tool Proficiency

### Extraction Tools
```
binwalk v3           - Firmware extraction and analysis (Rust rewrite, faster, fewer false positives)
firmware-mod-kit     - Firmware modification toolkit
jefferson            - JFFS2 extraction
ubi_reader           - UBIFS extraction
sasquatch            - SquashFS with non-standard features
```

### Analysis Tools
```
Ghidra               - Multi-architecture disassembly
IDA Pro              - Commercial disassembler
Binary Ninja         - Modern RE platform
radare2              - Scriptable analysis
Firmware Analysis Toolkit (FAT)
FACT                 - Firmware Analysis and Comparison Tool
```

### Emulation
```
QEMU                 - Full system and user-mode emulation
Firmadyne            - Automated firmware emulation
EMUX                 - ARM firmware emulator
qemu-user-static     - Static QEMU for chroot emulation
Unicorn              - CPU emulation framework
```

### Hardwar
