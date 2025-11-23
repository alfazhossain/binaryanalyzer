#!/usr/bin/env python3
"""
CTF Binary Analysis Tool - Advanced 
Author: V01D_SCR1PT
Version: 2.0
"""

import subprocess
import sys
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class BinaryAnalyzer:
    """Advanced binary analysis with exploit generation"""
    
    def __init__(self, binary_path: str):
        self.binary_path = Path(binary_path).resolve()
        if not self.binary_path.exists():
            print(f"{Colors.RED}[!] Error: Binary file not found: {binary_path}{Colors.ENDC}")
            sys.exit(1)
        
        self.binary_name = self.binary_path.name
        self.results = {
            'arch': None,
            'bits': None,
            'endian': 'little',
            'canary': None,
            'nx': None,
            'pie': None,
            'relro': None,
            'functions': [],
            'dangerous_funcs': [],
            'win_functions': [],
            'gadgets': [],
            'vulnerabilities': [],
        }
        
    def print_section(self, title: str, char: str = "="):
        """Print formatted section header"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{char*70}")
        print(f"{title.center(70)}")
        print(f"{char*70}{Colors.ENDC}\n")
    
    def run_command(self, cmd: List[str], ignore_errors: bool = False, timeout: int = 30) -> Optional[str]:
        """Run shell command and return output"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.binary_path.parent
            )
            if result.returncode != 0 and not ignore_errors:
                return None
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return None
    
    def analyze_file_type(self):
        """Basic file analysis"""
        self.print_section("📁 FILE TYPE & BASIC INFO")
        output = self.run_command(['file', str(self.binary_path)])
        if output:
            print(f"{Colors.GREEN}[+] File Information:{Colors.ENDC}")
            print(f"    {output.strip()}\n")
            
            # Parse details
            if '32-bit' in output:
                self.results['bits'] = 32
                self.results['arch'] = 'i386'
            elif '64-bit' in output:
                self.results['bits'] = 64
                self.results['arch'] = 'x86-64'
            
            if 'MSB' in output:
                self.results['endian'] = 'big'
            
            if 'ELF' in output:
                self.results['format'] = 'ELF'
            elif 'PE32' in output:
                self.results['format'] = 'PE'
            
            # Additional info
            print(f"{Colors.CYAN}[*] Architecture: {Colors.YELLOW}{self.results['arch']}")
            print(f"{Colors.CYAN}[*] Bits: {Colors.YELLOW}{self.results['bits']}-bit")
            print(f"{Colors.CYAN}[*] Endianness: {Colors.YELLOW}{self.results['endian']}{Colors.ENDC}")
    
    def analyze_security_protections(self):
        """Detailed security analysis"""
        self.print_section("🛡️  SECURITY PROTECTIONS (CRITICAL!)")
        
        # Try checksec first
        output = self.run_command(['checksec', '--file=' + str(self.binary_path)], ignore_errors=True)
        
        if not output:
            # Fallback to rabin2
            output = self.run_command(['rabin2', '-I', str(self.binary_path)])
        
        if output:
            # Parse security features
            canary = 'false' not in output.lower() if 'canary' in output.lower() else None
            nx = 'false' not in output.lower() if 'nx' in output.lower() else None
            pie = 'false' not in output.lower() if 'pie' in output.lower() or 'pic' in output.lower() else None
            relro = 'full' if 'full' in output.lower() else ('partial' if 'partial' in output.lower() else 'none')
            
            self.results['canary'] = canary
            self.results['nx'] = nx
            self.results['pie'] = pie
            self.results['relro'] = relro
            
            # Display with proper colors
            def status_color(enabled, text):
                if enabled:
                    return f"{Colors.GREEN}[✓] {text}: ENABLED{Colors.ENDC}"
                else:
                    return f"{Colors.RED}[✗] {text}: DISABLED (EXPLOITABLE!){Colors.ENDC}"
            
            print(status_color(canary, "Stack Canary"))
            print(status_color(nx, "NX (No Execute)"))
            print(status_color(pie, "PIE (Position Independent)"))
            print(f"{Colors.CYAN}[*] RELRO: {Colors.YELLOW}{relro.upper()}{Colors.ENDC}")
            
            print(f"\n{Colors.BOLD}Raw Security Info:{Colors.ENDC}")
            print(output)
    
    def analyze_strings_advanced(self):
        """Advanced string analysis with patterns"""
        self.print_section("🔍 STRING ANALYSIS")
        output = self.run_command(['strings', '-n', '4', str(self.binary_path)])
        
        if output:
            # Categorize strings
            categories = {
                'flags': [],
                'functions': [],
                'commands': [],
                'files': [],
                'secrets': [],
                'other': []
            }
            
            patterns = {
                'flags': [r'flag', r'ctf', r'HTB', r'picoCTF', r'{.*}'],
                'functions': [r'win|shell|admin|secret|backdoor|vuln|pwn'],
                'commands': [r'/bin/|system|exec|sh$|bash'],
                'files': [r'\.txt|\.flag|\.key|\.conf'],
                'secrets': [r'password|key|secret|token|admin'],
            }
            
            for line in output.split('\n'):
                line = line.strip()
                if not line or len(line) < 4:
                    continue
                
                categorized = False
                for category, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        if re.search(pattern, line, re.IGNORECASE):
                            categories[category].append(line)
                            categorized = True
                            break
                    if categorized:
                        break
            
            # Display categorized strings
            for category, strings in categories.items():
                if strings:
                    color = Colors.RED if category in ['flags', 'secrets'] else Colors.YELLOW
                    print(f"\n{color}[{category.upper()}]{Colors.ENDC}")
                    for s in strings[:15]:
                        print(f"    → {s}")
                    if len(strings) > 15:
                        print(f"    ... and {len(strings) - 15} more")
    
    def analyze_functions_deep(self):
        """Deep function analysis with disassembly"""
        self.print_section("⚙️  FUNCTION ANALYSIS")
        
        # Get function list
        r2_cmd = "aaa; afl"
        output = self.run_command(['r2', '-q', '-c', r2_cmd, str(self.binary_path)])
        
        if output:
            interesting_keywords = ['main', 'win', 'flag', 'vuln', 'admin', 'secret', 
                                   'shell', 'system', 'backdoor', 'pwn', 'roar', 'call']
            
            print(f"{Colors.GREEN}[+] All Functions:{Colors.ENDC}\n")
            
            for line in output.split('\n'):
                if not line.strip():
                    continue
                
                is_interesting = any(kw in line.lower() for kw in interesting_keywords)
                
                if is_interesting:
                    print(f"{Colors.RED}★ {line}{Colors.ENDC}")
                    self.results['win_functions'].append(line)
                else:
                    print(f"  {line}")
                
                # Store function names
                match = re.search(r'(sym\.\w+|main|entry\d+)', line)
                if match:
                    self.results['functions'].append(match.group(1))
            
            # Disassemble interesting functions
            self.disassemble_key_functions()
    
    def disassemble_key_functions(self):
        """Disassemble key functions"""
        self.print_section("📋 DISASSEMBLY OF KEY FUNCTIONS", "-")
        
        key_funcs = ['main', 'sym.secret_function', 'sym.vulnerable_roar', 
                     'sym.call_system', 'sym.read_flag', 'sym.win', 
                     'sym.vuln', 'sym.receive_feedback']
        
        for func in key_funcs:
            # Check if function exists
            check_cmd = f"aaa; s {func} 2>/dev/null"
            if self.run_command(['r2', '-q', '-c', check_cmd, str(self.binary_path)], ignore_errors=True):
                disasm_cmd = f"aaa; s {func}; pdf"
                output = self.run_command(['r2', '-q', '-c', disasm_cmd, str(self.binary_path)])
                
                if output and len(output) > 10:
                    print(f"\n{Colors.YELLOW}[*] Function: {func}{Colors.ENDC}")
                    print(f"{Colors.CYAN}{'─'*60}{Colors.ENDC}")
                    
                    # Highlight dangerous calls
                    for line in output.split('\n')[:50]:  # Limit lines
                        if any(danger in line.lower() for danger in ['call', 'system', 'exec', 'gets', 'strcpy']):
                            print(f"{Colors.RED}{line}{Colors.ENDC}")
                        else:
                            print(line)
                    
                    if len(output.split('\n')) > 50:
                        print(f"\n{Colors.YELLOW}... (truncated, {len(output.split('\n')) - 50} more lines){Colors.ENDC}")
    
    def analyze_imports_exports(self):
        """Analyze imported and exported functions"""
        self.print_section("📦 IMPORTS & DANGEROUS FUNCTIONS")
        
        # Imports
        output = self.run_command(['rabin2', '-i', str(self.binary_path)])
        
        if output:
            dangerous = {
                'buffer_overflow': ['gets', 'strcpy', 'strcat', 'sprintf', 'scanf', 'vsprintf'],
                'format_string': ['printf', 'fprintf', 'sprintf', 'snprintf'],
                'command_injection': ['system', 'exec', 'popen', 'execve'],
                'file_ops': ['fopen', 'fread', 'fwrite', 'read', 'write'],
            }
            
            found_dangerous = {k: [] for k in dangerous.keys()}
            
            print(f"{Colors.GREEN}[+] Imported Functions:{Colors.ENDC}\n")
            
            for line in output.split('\n'):
                if not line.strip() or line.startswith('[') or line.startswith('nth'):
                    continue
                
                is_dangerous = False
                for category, funcs in dangerous.items():
                    for func in funcs:
                        if func in line.lower():
                            found_dangerous[category].append(line)
                            is_dangerous = True
                            break
                
                if is_dangerous:
                    print(f"{Colors.RED}  [!] {line}{Colors.ENDC}")
                else:
                    print(f"    {line}")
            
            # Summary
            print(f"\n{Colors.BOLD}Dangerous Function Summary:{Colors.ENDC}")
            for category, funcs in found_dangerous.items():
                if funcs:
                    print(f"{Colors.RED}  [{category.upper()}]: {len(funcs)} found{Colors.ENDC}")
                    self.results['dangerous_funcs'].extend(funcs)
    
    def find_rop_gadgets(self):
        """Find ROP gadgets"""
        self.print_section("🔗 ROP GADGETS")
        
        # Try ROPgadget
        output = self.run_command(['ROPgadget', '--binary', str(self.binary_path), '--depth', '5'], 
                                 ignore_errors=True, timeout=15)
        
        if output:
            print(f"{Colors.GREEN}[+] Useful ROP Gadgets:{Colors.ENDC}\n")
            
            # Filter useful gadgets
            useful_patterns = ['pop rdi', 'pop rsi', 'pop rdx', 'pop eax', 'pop ebx', 
                              'syscall', 'int 0x80', 'call', 'ret', '/bin/sh']
            
            gadgets = []
            for line in output.split('\n'):
                if any(pattern in line.lower() for pattern in useful_patterns):
                    gadgets.append(line)
            
            # Display
            for gadget in gadgets[:30]:
                if 'pop' in gadget.lower() or 'syscall' in gadget.lower():
                    print(f"{Colors.YELLOW}  {gadget}{Colors.ENDC}")
                else:
                    print(f"    {gadget}")
            
            if len(gadgets) > 30:
                print(f"\n{Colors.CYAN}... and {len(gadgets) - 30} more gadgets{Colors.ENDC}")
            
            self.results['gadgets'] = gadgets
        else:
            print(f"{Colors.YELLOW}[!] ROPgadget not found. Install: pip install ropgadget{Colors.ENDC}")
            
            # Fallback: check for specific gadgets manually
            print(f"\n{Colors.CYAN}[*] Checking for common gadgets with r2...{Colors.ENDC}")
            gadget_cmd = 'aaa; "/R pop rdi"'
            output = self.run_command(['r2', '-q', '-c', gadget_cmd, str(self.binary_path)])
            if output:
                print(output[:500])
    
    def analyze_plt_got(self):
        """Analyze PLT and GOT"""
        self.print_section("🎯 PLT & GOT ANALYSIS")
        
        # PLT
        plt_output = self.run_command(['objdump', '-d', '-j', '.plt', str(self.binary_path)], 
                                      ignore_errors=True)
        
        if plt_output:
            print(f"{Colors.GREEN}[+] PLT Entries:{Colors.ENDC}\n")
            for line in plt_output.split('\n')[:30]:
                if 'plt' in line.lower() or '@' in line:
                    print(f"  {line}")
        
        # GOT
        print(f"\n{Colors.GREEN}[+] GOT Entries:{Colors.ENDC}\n")
        got_output = self.run_command(['objdump', '-R', str(self.binary_path)], ignore_errors=True)
        
        if got_output:
            for line in got_output.split('\n')[:30]:
                if line.strip() and not line.startswith('OFFSET'):
                    print(f"  {line}")
    
    def detect_vulnerabilities_advanced(self):
        """Advanced vulnerability detection"""
        self.print_section("🚨 VULNERABILITY ASSESSMENT")
        
        vulns = []
        exploit_chain = []
        
        # Check protections
        if not self.results['canary']:
            vuln = "BUFFER OVERFLOW: No stack canary"
            vulns.append(vuln)
            exploit_chain.append("1. Overflow buffer to overwrite return address")
        
        if not self.results['nx']:
            vuln = "SHELLCODE EXECUTION: NX disabled"
            vulns.append(vuln)
            exploit_chain.append("2. Inject and execute shellcode directly")
        
        if not self.results['pie']:
            vuln = "FIXED ADDRESSES: No PIE"
            vulns.append(vuln)
            exploit_chain.append("3. Use fixed addresses for ROP/ret2libc")
        
        if self.results['relro'] in ['partial', 'none']:
            vuln = "GOT OVERWRITE: Partial/No RELRO"
            vulns.append(vuln)
            exploit_chain.append("4. Overwrite GOT entries")
        
        # Check dangerous functions
        if self.results['dangerous_funcs']:
            vuln = "DANGEROUS FUNCTIONS: Buffer overflow vectors"
            vulns.append(vuln)
        
        # Check for win functions
        if self.results['win_functions']:
            print(f"{Colors.RED}[!!!] WIN FUNCTIONS FOUND:{Colors.ENDC}\n")
            for func in self.results['win_functions']:
                print(f"  {Colors.YELLOW}→ {func}{Colors.ENDC}")
            exploit_chain.insert(0, "0. Jump to win function directly!")
        
        # Display vulnerabilities
        if vulns:
            print(f"\n{Colors.BOLD}{Colors.RED}Critical Vulnerabilities:{Colors.ENDC}\n")
            for v in vulns:
                print(f"  [!] {v}")
            
            print(f"\n{Colors.BOLD}{Colors.GREEN}Suggested Exploit Chain:{Colors.ENDC}\n")
            for step in exploit_chain:
                print(f"  {step}")
        
        self.results['vulnerabilities'] = vulns
    
    def generate_exploit_template(self):
        """Generate pwntools exploit template"""
        self.print_section("💥 EXPLOIT TEMPLATE (PWNTOOLS)")
        
        template = f"""#!/usr/bin/env python3
# Exploit for {self.binary_name}
# Generated by binary_analyzer.py

from pwn import *

# Configuration
binary_path = './{self.binary_name}'
elf = ELF(binary_path)
context.binary = elf
context.log_level = 'debug'

# Addresses (update these!)
"""
        
        # Add win function addresses
        if self.results['win_functions']:
            template += "\n# Win functions found:\n"
            for func in self.results['win_functions'][:5]:
                match = re.search(r'0x[0-9a-f]+', func)
                if match:
                    addr = match.group(0)
                    func_name = re.search(r'(sym\.\w+|main)', func)
                    if func_name:
                        template += f"win_addr = {addr}  # {func_name.group(1)}\n"
        
        # Add gadgets
        if self.results['gadgets']:
            template += "\n# Useful ROP gadgets:\n"
            for gadget in self.results['gadgets'][:10]:
                match = re.search(r'0x[0-9a-f]+', gadget)
                if match:
                    addr = match.group(0)
                    template += f"# {gadget[:60]}\n"
        
        template += f"""
# Exploit function
def exploit():
    # Local process
    p = process(binary_path)
    
    # Remote connection (uncomment for remote)
    # p = remote('host', port)
    
    # Build payload
    offset = 0  # TODO: Find offset with pattern_create/pattern_offset
    payload = b'A' * offset
    
"""
        
        # Add exploit suggestion based on architecture
        if self.results['bits'] == 32:
            template += """    # 32-bit exploit
    payload += p32(win_addr)  # Return address
    """
        else:
            template += """    # 64-bit exploit
    payload += p64(win_addr)  # Return address
    """
        
        template += """
    # Send payload
    p.sendline(payload)
    
    # Get flag
    p.interactive()

if __name__ == '__main__':
    exploit()
"""
        
        print(f"{Colors.GREEN}[+] Generated Exploit Template:{Colors.ENDC}\n")
        print(f"{Colors.CYAN}{template}{Colors.ENDC}")
        
        # Save to file
        exploit_file = self.binary_path.parent / f"exploit_{self.binary_name}.py"
        try:
            with open(exploit_file, 'w') as f:
                f.write(template)
            print(f"\n{Colors.GREEN}[+] Template saved to: {exploit_file}{Colors.ENDC}")
        except:
            pass
    
    def generate_summary(self):
        """Generate exploit summary"""
        self.print_section("📊 QUICK EXPLOIT SUMMARY")
        
        print(f"{Colors.BOLD}Binary: {self.binary_name}{Colors.ENDC}\n")
        
        print(f"{Colors.CYAN}Architecture:{Colors.ENDC} {self.results['arch']} ({self.results['bits']}-bit)")
        
        print(f"\n{Colors.CYAN}Security:{Colors.ENDC}")
        print(f"  Canary: {'✓' if self.results['canary'] else '✗'}")
        print(f"  NX: {'✓' if self.results['nx'] else '✗'}")
        print(f"  PIE: {'✓' if self.results['pie'] else '✗'}")
        print(f"  RELRO: {self.results['relro']}")
        
        if self.results['win_functions']:
            print(f"\n{Colors.RED}Win Functions: {len(self.results['win_functions'])}{Colors.ENDC}")
        
        if self.results['dangerous_funcs']:
            print(f"{Colors.YELLOW}Dangerous Functions: {len(self.results['dangerous_funcs'])}{Colors.ENDC}")
        
        if self.results['vulnerabilities']:
            print(f"{Colors.RED}Vulnerabilities: {len(self.results['vulnerabilities'])}{Colors.ENDC}")
        
        print(f"\n{Colors.GREEN}[+] Next Steps:{Colors.ENDC}")
        print(f"  1. Run: gdb -q ./{self.binary_name}")
        print(f"  2. Test: python3 exploit_{self.binary_name}.py")
        print(f"  3. Find offset: cyclic 200 (in pwndbg)")
        print(f"  4. Debug with: gdb -ex 'break main' -ex 'run' ./{self.binary_name}")
    
    def run_full_analysis(self):
        """Run complete analysis"""
        print(f"\n{Colors.BOLD}{Colors.HEADER}")
        print("╔" + "═"*68 + "╗")
        print("║" + "  CTF BINARY ANALYZER v2.0 - Advanced Edition  ".center(68) + "║")
        print("║" + "  by alfaz404  ".center(68) + "║")
        print("╚" + "═"*68 + "╝")
        print(f"{Colors.ENDC}")
        
        print(f"\n{Colors.CYAN}[*] Target: {Colors.BOLD}{self.binary_name}{Colors.ENDC}")
        print(f"{Colors.CYAN}[*] Path: {self.binary_path}{Colors.ENDC}")
        
        # Run all analysis
        self.analyze_file_type()
        self.analyze_security_protections()
        self.analyze_strings_advanced()
        self.analyze_imports_exports()
        self.analyze_functions_deep()
        self.find_rop_gadgets()
        self.analyze_plt_got()
        self.detect_vulnerabilities_advanced()
        self.generate_exploit_template()
        self.generate_summary()
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}")
        print("╔" + "═"*68 + "╗")
        print("║" + "  ANALYSIS COMPLETE - READY TO EXPLOIT!  ".center(68) + "║")
        print("╚" + "═"*68 + "╝")
        print(f"{Colors.ENDC}\n")

def check_dependencies():
    """Check required tools"""
    tools = {
        'required': ['file', 'strings', 'rabin2', 'r2', 'objdump', 'nm'],
        'optional': ['checksec', 'ROPgadget', 'gdb', 'pwndbg']
    }
    
    missing_req = []
    missing_opt = []
    
    for tool in tools['required']:
        if subprocess.run(['which', tool], capture_output=True).returncode != 0:
            missing_req.append(tool)
    
    for tool in tools['optional']:
        if subprocess.run(['which', tool], capture_output=True).returncode != 0:
            missing_opt.append(tool)
    
    if missing_req:
        print(f"{Colors.RED}[!] Missing required: {', '.join(missing_req)}{Colors.ENDC}")
        print(f"{Colors.YELLOW}Install: sudo apt install radare2 binutils{Colors.ENDC}\n")
        return False
    
    if missing_opt:
        print(f"{Colors.YELLOW}[!] Missing optional: {', '.join(missing_opt)}{Colors.ENDC}")
        print(f"Install: pip install ropgadget pwntools{Colors.ENDC}\n")
    
    return True

def main():
    if len(sys.argv) != 2:
        print(f"{Colors.BOLD}Usage:{Colors.ENDC} {sys.argv[0]} <binary>")
        print(f"Example: {Colors.CYAN}{sys.argv[0]} ./pwn1{Colors.ENDC}")
        sys.exit(1)
    
    check_dependencies()
    
    analyzer = BinaryAnalyzer(sys.argv[1])
    analyzer.run_full_analysis()

if __name__ == "__main__":
    main()
