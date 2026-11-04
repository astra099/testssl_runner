## testssl_runner

testssl_runner.py is a multi-target runner designed to streamline bulk SSL/TLS scanning. It preserves native terminal color output, flags weak ciphers, and automatically saves a master summary in CSV format while archiving individual results for each domain.

## Flags

| Flag | Description |
|-------|-------------|
| `<domain> [domain...]` | *(Python only)* Scan one or more domains/IPs given directly, space-separated. |
| `-f <file>` | Scan every domain listed in `<file>` (one per line). |
| `-o [directory]` | Save each scan to its own file in `[directory]` (default name if omitted: `testssl-output-DD-MM-YYYY-HHMM`). |
| `-os` | Print each scan's output to the terminal. |
| `-t <path>` | Use a specific testssl binary instead of auto-detecting one. |
| `--report [dir]` | *(Python only)* Generate `summary.csv`. Saved to `[dir]` if given, else the `-o` directory, else the current directory. |
| `--detect` | Show what testssl installation will be used, without scanning anything. |
| `--interactive` | Menu-driven mode. |
| `-h`, `--help` | Show help. |


## Color Behavior

### Terminal Output (`-os` flag)
✅ **FULL COLORS** - Shows original testssl colors (green/cyan/orange/red)
- Green: OK/secure findings
- Cyan: Information
- Orange: Warnings/offered but concerning
- Red: Vulnerabilities

### File Output (`-o` flag only)
❌ **NO COLORS** - Plain text saved to files (for better parsing/compatibility)

### Both Output (`-o` + `-os` flags)
✅ **Terminal shows colors**
❌ **File saves without colors**

## Examples

### Example 1: Terminal with Colors
```bash
./testssl_runner.py example.com
```
```bash
./testssl_runner.py example1.com example2.com example3.com
```
```bash
./testssl_runner.py -f domains.txt -os
```
**Result:** Full colored output in terminal like your screenshots

### Example 2: File without Colors
```bash
./testssl_runner.py -f domains.txt -o results
```
**Result:** Plain text files saved to results/ directory

### Example 3: Both (Colors in Terminal, Plain in Files)
```bash
./testssl_runner.py -f domains.txt -o results -os
```
**Result:** 
- Terminal shows colored output
- Files contain plain text (no color codes)

## Visual Examples

### Cipher Categories 
<img width="844" height="488" alt="Cipher Categories" src="https://github.com/user-attachments/assets/d7e9e2ba-e952-493f-a327-3b537a4198c6" />

### server's cipher preferences
<img width="1143" height="758" alt="cipher-preferences" src="https://github.com/user-attachments/assets/0d74f079-a933-4eed-a1d4-9446d2e03853" />

### Vulnerabilities 
<img width="1498" height="423" alt="Vulnerabilities" src="https://github.com/user-attachments/assets/07a36d46-7a4f-47aa-a0f6-0e1008ae95c3" />

## File Output Remains Clean

Files saved with `-o` remain **color-code-free** for:
- Easy parsing with grep/awk
- Clean text editor viewing
- Report generation
- CI/CD integration

## Quick Reference

| Command | Terminal | File |
|---------|----------|------|
| `-os` | ✅ Colors | - |
| `-o` | - | ❌ No colors |
| `-o -os` | ✅ Colors | ❌ No colors |

## Benefits

1. **Visual Scanning** - Quickly spot vulnerabilities by color
2. **Match Documentation** - Colors match testssl docs and tutorials
3. **Professional Reports** - Terminal sessions look like the real thing
4. **File Compatibility** - Saved files remain clean for parsing
5. **Color Mode:** `--color 3` (full colors for terminal)

