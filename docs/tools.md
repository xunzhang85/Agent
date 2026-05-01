# Security Tools Reference

## Built-in Tools

### Web Security

| Tool | Command | Description |
|------|---------|-------------|
| curl | `curl` | HTTP requests and response analysis |
| sqlmap | `sqlmap` | Automatic SQL injection detection |
| nikto | `nikto` | Web server vulnerability scanner |
| gobuster | `gobuster` | Directory/file brute-forcing |
| ffuf | `ffuf` | Fast web fuzzer |
| hydra | `hydra` | Network logon cracker |

### Cryptography

| Tool | Command | Description |
|------|---------|-------------|
| openssl | `openssl` | Cryptographic operations |
| john | `john` | John the Ripper password cracker |
| hashcat | `hashcat` | Advanced password recovery |

### Binary Exploitation

| Tool | Command | Description |
|------|---------|-------------|
| gdb | `gdb` | GNU Debugger |
| ropper | `ropper` | ROP gadget finder |
| checksec | `checksec` | Binary security checker |
| pwntools | `pwntools` | CTF exploitation toolkit |

### Reverse Engineering

| Tool | Command | Description |
|------|---------|-------------|
| radare2 | `r2` | Reverse engineering framework |
| objdump | `objdump` | Object file dumper |
| readelf | `readelf` | ELF file analyzer |
| angr | `angr` | Symbolic execution engine |
| ghidra | `ghidra` | NSA's reverse engineering tool |

### Forensics

| Tool | Command | Description |
|------|---------|-------------|
| binwalk | `binwalk` | Firmware analysis |
| steghide | `steghide` | Steganography extraction |
| exiftool | `exiftool` | Metadata extraction |
| volatility | `vol.py` | Memory forensics |
| foremost | `foremost` | File carving |
| tshark | `tshark` | Network capture analysis |

## Custom Tools

Register custom tools via Python API:

```python
from agent.tools.registry import ToolRegistry

registry = ToolRegistry()

def my_scanner(target: str) -> str:
    """Custom scanner implementation."""
    # Your tool logic here
    return f"Scanned {target}"

registry.register_custom(
    "my_scanner",
    my_scanner,
    description="Custom vulnerability scanner",
)
```

## Tool Discovery

Tools are automatically discovered on startup. Check availability:

```bash
agent tools
```

Output:
```
🔧 Security Tools
┌──────────────┬──────────┬──────────┬──────────────────────────┐
│ Tool         │ Category │ Status   │ Description              │
├──────────────┼──────────┼──────────┼──────────────────────────┤
│ nmap         │ network  │ ✅ Ready │ Network exploration      │
│ curl         │ web      │ ✅ Ready │ HTTP requests            │
│ sqlmap       │ web      │ ❌ Missing│ SQL injection           │
│ ...          │ ...      │ ...      │ ...                      │
└──────────────┴──────────┴──────────┴──────────────────────────┘
Tools: 15/20 available
```
