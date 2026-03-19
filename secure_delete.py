"""
Secure File Deletion Tool for Windows
Overwrites file data before deletion to make forensic recovery difficult.

Levels:
  1 - Quick:    1 pass random overwrite + delete
  2 - Standard: 3 passes (zeros, ones, random) + truncate + rename + delete
  3 - Paranoid: 7 passes (DoD 5220.22-M inspired) + truncate + multiple renames
                + delete + alternate data stream clearing + attribute clearing

Note: On SSDs, overwriting is unreliable due to wear-leveling. Full-disk
encryption (BitLocker) is the recommended approach for SSDs.
"""

import argparse
import ctypes
import os
import random
import string
import sys
import time


# --- Low-level Windows helpers ---

def _flush_to_disk(f):
    """Force the OS to flush file buffers to the physical disk."""
    f.flush()
    os.fsync(f.fileno())


def _clear_file_attributes(path: str):
    """Remove hidden/system/readonly attributes so the file can be modified."""
    try:
        ctypes.windll.kernel32.SetFileAttributesW(path, 0x80)  # FILE_ATTRIBUTE_NORMAL
    except Exception:
        pass


def _clear_alternate_data_streams(path: str):
    """
    Delete NTFS alternate data streams (ADS) attached to the file.
    Uses the Windows API FindFirstStreamW / FindNextStreamW.
    """
    try:
        from ctypes import wintypes

        class WIN32_FIND_STREAM_DATA(ctypes.Structure):
            _fields_ = [
                ("StreamSize", ctypes.c_longlong),
                ("cStreamName", ctypes.c_wchar * 296),
            ]

        kernel32 = ctypes.windll.kernel32
        FindFirstStreamW = kernel32.FindFirstStreamW
        FindFirstStreamW.restype = wintypes.HANDLE
        FindNextStreamW = kernel32.FindNextStreamW
        FindNextStreamW.restype = wintypes.BOOL

        data = WIN32_FIND_STREAM_DATA()
        handle = FindFirstStreamW(path, 0, ctypes.byref(data), 0)
        INVALID = wintypes.HANDLE(-1).value

        if handle == INVALID:
            return

        streams_to_delete = []
        while True:
            name = data.cStreamName
            # Skip the default data stream "::$DATA"
            if name and name != "::$DATA":
                stream_name = name.split(":")[1] if ":" in name else None
                if stream_name:
                    streams_to_delete.append(stream_name)
            if not FindNextStreamW(handle, ctypes.byref(data)):
                break
        kernel32.FindClose(handle)

        for stream_name in streams_to_delete:
            full = f"{path}:{stream_name}"
            try:
                # Overwrite the ADS before deleting
                with open(full, "wb") as f:
                    f.write(os.urandom(64))
                    _flush_to_disk(f)
                os.remove(full)
            except OSError:
                pass
    except Exception:
        pass


# --- Overwrite patterns ---

def _write_pattern(f, size: int, pattern: bytes):
    """Write a repeating byte pattern over the entire file size."""
    chunk_size = 1024 * 1024  # 1 MB
    chunk = pattern * (chunk_size // len(pattern) + 1)
    chunk = chunk[:chunk_size]
    written = 0
    while written < size:
        to_write = min(chunk_size, size - written)
        f.seek(written)
        f.write(chunk[:to_write])
        written += to_write
    _flush_to_disk(f)


def _write_random(f, size: int):
    """Write cryptographically random data over the entire file size."""
    chunk_size = 1024 * 1024
    written = 0
    while written < size:
        to_write = min(chunk_size, size - written)
        f.seek(written)
        f.write(os.urandom(to_write))
        written += to_write
    _flush_to_disk(f)


# --- Rename obfuscation ---

def _random_name(length: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _rename_file(path: str) -> str:
    """Rename to a random name in the same directory. Returns new path."""
    directory = os.path.dirname(path)
    new_path = os.path.join(directory, _random_name())
    try:
        os.rename(path, new_path)
        return new_path
    except OSError:
        return path


# --- Core deletion routines per level ---

def _secure_delete_quick(path: str, file_size: int, verbose: bool):
    """Level 1 — single random overwrite pass."""
    if verbose:
        print("  [1/1] Random overwrite...")
    with open(path, "r+b") as f:
        _write_random(f, file_size)


def _secure_delete_standard(path: str, file_size: int, verbose: bool):
    """Level 2 — three passes: zeros, ones, random."""
    passes = [
        ("Zeros  (0x00)", b"\x00"),
        ("Ones   (0xFF)", b"\xFF"),
        ("Random",        None),
    ]
    for i, (label, pattern) in enumerate(passes, 1):
        if verbose:
            print(f"  [{i}/{len(passes)}] {label}...")
        with open(path, "r+b") as f:
            if pattern:
                _write_pattern(f, file_size, pattern)
            else:
                _write_random(f, file_size)


def _secure_delete_paranoid(path: str, file_size: int, verbose: bool):
    """
    Level 3 — seven passes inspired by DoD 5220.22-M + Gutmann extras.
    Pass 1: 0x00
    Pass 2: 0xFF
    Pass 3: Random
    Pass 4: 0x55 (alternating bits)
    Pass 5: 0xAA (inverse alternating bits)
    Pass 6: Random
    Pass 7: 0x00 (final clean)
    """
    passes = [
        ("Zeros       (0x00)", b"\x00"),
        ("Ones        (0xFF)", b"\xFF"),
        ("Random #1",         None),
        ("Alt bits    (0x55)", b"\x55"),
        ("Inv alt     (0xAA)", b"\xAA"),
        ("Random #2",         None),
        ("Final zeros (0x00)", b"\x00"),
    ]
    for i, (label, pattern) in enumerate(passes, 1):
        if verbose:
            print(f"  [{i}/{len(passes)}] {label}...")
        with open(path, "r+b") as f:
            if pattern:
                _write_pattern(f, file_size, pattern)
            else:
                _write_random(f, file_size)


# --- Main entry point ---

LEVELS = {
    1: ("Quick",    "1 random pass + delete",                              _secure_delete_quick),
    2: ("Standard", "3 passes (zeros/ones/random) + rename + delete",      _secure_delete_standard),
    3: ("Paranoid", "7 passes (DoD-inspired) + ADS clear + rename + delete", _secure_delete_paranoid),
}


def secure_delete(path: str, level: int = 2, verbose: bool = True) -> bool:
    """
    Securely delete a file at the given path.

    Args:
        path:    Absolute or relative path to the file.
        level:   Security level (1=Quick, 2=Standard, 3=Paranoid).
        verbose: Print progress messages.

    Returns:
        True if the file was successfully deleted.
    """
    path = os.path.abspath(path)

    if not os.path.isfile(path):
        print(f"Error: '{path}' is not a file or does not exist.", file=sys.stderr)
        return False

    if level not in LEVELS:
        print(f"Error: level must be 1, 2, or 3.", file=sys.stderr)
        return False

    name, description, overwrite_fn = LEVELS[level]
    file_size = os.path.getsize(path)

    if verbose:
        print(f"Target : {path}")
        print(f"Size   : {file_size:,} bytes")
        print(f"Level  : {level} — {name} ({description})")
        print()

    start = time.perf_counter()

    # Step 1: Clear attributes so we can write freely
    _clear_file_attributes(path)

    # Step 2: Clear NTFS alternate data streams (level 3 only)
    if level >= 3:
        if verbose:
            print("  Clearing alternate data streams...")
        _clear_alternate_data_streams(path)

    # Step 3: Overwrite passes
    if file_size > 0:
        overwrite_fn(path, file_size, verbose)

    # Step 4: Truncate to zero
    if level >= 2:
        if verbose:
            print("  Truncating to 0 bytes...")
        with open(path, "wb") as f:
            _flush_to_disk(f)

    # Step 5: Rename to random name(s) to scrub directory entry
    if level >= 2:
        renames = 1 if level == 2 else 5
        for i in range(renames):
            if verbose:
                print(f"  Renaming ({i + 1}/{renames})...")
            path = _rename_file(path)

    # Step 6: Delete
    try:
        os.remove(path)
    except OSError as e:
        print(f"Error deleting file: {e}", file=sys.stderr)
        return False

    elapsed = time.perf_counter() - start

    if verbose:
        print()
        print(f"Done. File securely deleted in {elapsed:.2f}s.")

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Securely delete files to resist forensic recovery.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Security levels:
  1  Quick     — 1 random overwrite pass, then delete.
                 Fast. Defeats basic undelete tools.
  2  Standard  — 3 overwrite passes (zeros, ones, random),
                 truncate, rename, delete.
                 Defeats most software-based recovery.
  3  Paranoid  — 7 overwrite passes (DoD 5220.22-M inspired),
                 NTFS ADS clearing, multiple renames, delete.
                 Maximum software-level protection.

Note: On SSDs, overwriting may not reach the actual flash cells due
to wear-leveling. Use full-disk encryption for SSD security.
        """,
    )
    parser.add_argument("file", help="Path to the file to securely delete")
    parser.add_argument(
        "-l", "--level",
        type=int,
        choices=[1, 2, 3],
        default=2,
        help="Security level: 1=Quick, 2=Standard (default), 3=Paranoid",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress progress output",
    )
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip confirmation prompt",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"Error: '{args.file}' not found.", file=sys.stderr)
        sys.exit(1)

    if not args.yes:
        abs_path = os.path.abspath(args.file)
        size = os.path.getsize(abs_path)
        level_name = LEVELS[args.level][0]
        print(f"About to PERMANENTLY destroy:")
        print(f"  {abs_path}  ({size:,} bytes)")
        print(f"  Level {args.level} — {level_name}")
        print()
        answer = input("Are you sure? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted.")
            sys.exit(0)

    success = secure_delete(args.file, level=args.level, verbose=not args.quiet)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
