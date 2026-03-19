# Somewhat Safe file destroyer

A Windows command-line tool for securely deleting files by overwriting their contents before removal, making forensic recovery significantly harder.

> **SSD Warning:** On solid-state drives, wear-leveling means the OS cannot guarantee which physical flash cells are overwritten. For SSDs, full-disk encryption (e.g. Veracrypt) is the recommended approach — when the key is destroyed, all data becomes unrecoverable.

## How It Works

Instead of simply removing a file's directory entry (which leaves the data on disk), Secure Delete:

1. **Overwrites** the file contents with specific byte patterns and/or random data
2. **Truncates** the file to zero bytes (hides original file size)
3. **Renames** the file to random strings (scrubs the original filename from directory entries)
4. **Deletes** the file

## Security Levels

| Level | Name | Passes | Techniques | Use Case |
|-------|------|--------|------------|----------|
| 1 | **Quick** | 1 | Random overwrite, delete | Fast disposal — defeats basic undelete tools (Recuva, etc.) |
| 2 | **Standard** | 3 | Zeros + ones + random overwrite, truncate, rename, delete | General use — defeats most software-based recovery |
| 3 | **Paranoid** | 7 | DoD 5220.22-M inspired patterns (`0x00`, `0xFF`, random, `0x55`, `0xAA`, random, `0x00`), NTFS alternate data stream clearing, attribute reset, 5x rename, truncate, delete | Maximum protection — resists advanced forensic tools |

### What Each Level Covers

```
                        Level 1    Level 2    Level 3
Overwrite passes           1          3          7
Truncate to 0 bytes        -          x          x
Rename obfuscation         -          1x         5x
Clear file attributes      x          x          x
Clear NTFS ADS             -          -          x
```

## Installation

No dependencies required — uses only the Python standard library and Windows APIs via `ctypes`.

```bash
git clone https://github.com/YOUR_USERNAME/secure-delete.git
cd secure-delete
```

Requires Python 3.6+.

## Usage

### Command Line

```bash
# Standard deletion (level 2, default)
python secure_delete.py secret.docx

# Quick single-pass deletion
python secure_delete.py -l 1 secret.docx

# Paranoid mode, skip confirmation prompt
python secure_delete.py -l 3 -y secret.docx

# Quiet mode (no progress output)
python secure_delete.py -l 2 -q -y secret.docx
```

### As a Library

```python
from secure_delete import secure_delete

# Returns True on success
secure_delete("path/to/file.txt", level=2, verbose=False)
```

### Options

| Flag | Description |
|------|-------------|
| `-l`, `--level` | Security level: `1` (Quick), `2` (Standard, default), `3` (Paranoid) |
| `-q`, `--quiet` | Suppress progress output |
| `-y`, `--yes` | Skip the confirmation prompt |

## Example Output

```
$ python secure_delete.py -l 3 secret.docx
About to PERMANENTLY destroy:
  C:\Users\you\Documents\secret.docx  (145,920 bytes)
  Level 3 — Paranoid

Are you sure? [y/N] y
Target : C:\Users\you\Documents\secret.docx
Size   : 145,920 bytes
Level  : 3 — Paranoid (7 passes (DoD-inspired) + ADS clear + rename + delete)

  Clearing alternate data streams...
  [1/7] Zeros       (0x00)...
  [2/7] Ones        (0xFF)...
  [3/7] Random #1...
  [4/7] Alt bits    (0x55)...
  [5/7] Inv alt     (0xAA)...
  [6/7] Random #2...
  [7/7] Final zeros (0x00)...
  Truncating to 0 bytes...
  Renaming (1/5)...
  Renaming (2/5)...
  Renaming (3/5)...
  Renaming (4/5)...
  Renaming (5/5)...

Done. File securely deleted in 0.08s.
```

## Limitations

- **SSDs**: Wear-leveling makes in-place overwriting unreliable. Use full-disk encryption instead.
- **Journaling filesystems**: NTFS may retain small file fragments or metadata in its journal.
- **Copy-on-write filesystems**: ZFS, Btrfs, and ReFS do not overwrite in place by design.
- **Cloud/sync services**: If the file was synced (OneDrive, Dropbox, etc.), copies may exist on remote servers.
- **System caches**: Windows may cache file contents in memory, pagefile, or thumbnail caches.

This tool provides the best available software-level protection on traditional HDDs with NTFS. For maximum security, combine with full-disk encryption.

## License

MIT License

Copyright (c) 2026 alcachofo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
