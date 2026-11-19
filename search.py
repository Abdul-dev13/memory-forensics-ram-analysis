#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  Topic 15 — Memory Forensics: Analyzing RAM for Digital Evidence
  search.py — RAM Dump Keyword Search Tool
================================================================================
  Author       : Abdul Ghafoor — S25BINCE1M04017
  Course       : Introduction to Digital Forensics
  Teacher      : Engr. Rafia Durrani
  Programme    : BS Cyber Security & Digital Forensics (4th Semester)
  University   : The Islamia University of Bahawalpur
  Submission   : Final Project — Code (due 1 December 2026)

  PURPOSE
  -------
  This script searches a raw RAM dump (.mem file captured with FTK Imager)
  for six test keywords and counts how many times each keyword occurs.

  A count greater than zero proves that the data was present in volatile
  memory (RAM) at the moment the dump was taken — even for data that was
  never saved to the hard disk, such as a website visited in Chrome
  Incognito mode or text typed in Notepad and never saved.

  The same script is run on two dumps to demonstrate volatility:
    1. memory-test-2.mem               — taken while the test programs
                                         were still open.
    2. memory-test-2-after-poweroff.mem — taken after a full shut down
                                         and restart, before reopening
                                         the test programs.

  ETHICAL NOTE
  ------------
  This tool was used ONLY on my own laptop, on my
  own test data. No other person's computer, account, or data was
  accessed. No password was collected, used, or displayed.

  HOW TO RUN
  ----------
  1. Keep this file in:   D:\\Forensics\\MemoryForensics\\search.py
  2. Open PowerShell and go to that folder:
         D:
         cd \\Forensics\\MemoryForensics
  3. Run it with the default dump path written in the code below:
         python search.py
     Or pass a different dump file as an argument (recommended):
         python search.py "D:\\Forensics\\MemoryForensics\\dump\\memory-test-2.mem"
         python search.py "D:\\Forensics\\MemoryForensics\\dump\\memory-test-2-after-poweroff.mem"

  REQUIREMENTS
  ------------
  Python 3.11 (tested with Python 3.11.9 on Windows). No extra libraries
  are needed — only the Python standard library is used.

  RECORDED RESULTS (from my own runs, 18 November 2026)
  ---------------------------------------------------------------
  Dump 1 — memory-test-2.mem (5,473,501,184 bytes)
    SHA-256: 648795D2359B5A021BEB506A645D4E89E7F1566CC247A230B9C82B03E460CC71
    safeshieldx : 1849 | pinterest : 4429 | memory forensics test file : 3
    notepad.exe : 32   | chrome.exe : 198 | Projects.pdf : 2

  Dump 2 — memory-test-2-after-poweroff.mem
    SHA-256: 66F722DD0D1C331583BD2137A6D45E49B9B76C24E60FD230E5791DCA9FAD2418
    safeshieldx : 9410 | pinterest : 4224 | memory forensics test file : 4
    notepad.exe : 177  | chrome.exe : 918 | Projects.pdf : 1

  Interpretation: the unsaved Notepad text and the open PDF fall to
  almost zero after power-off, which proves RAM is volatile. Browser
  terms can still appear in Dump 2 because Windows and Chrome restore /
  cache data on restart — the comparison is explained in the report.
================================================================================
"""

import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# 1. CONFIGURATION — edit only this section to search a different dump
# ---------------------------------------------------------------------------

# Default dump file. This is used when no file is given on the command line.
# The r"..." (raw string) prefix is needed so Windows backslashes are
# read literally and are not treated as escape characters.
DEFAULT_PATH = r"D:\Forensics\MemoryForensics\dump\memory-test-2.mem"

# The six keywords to search for, written as bytes (b"...") because a RAM
# dump is binary data, not a text file. The search is case-sensitive,
# exactly as in the original practical work.
#
#   Keyword                          What it proves
#   -------------------------------  ----------------------------------------
#   safeshieldx                      Website visited in Chrome Incognito
#   pinterest                        Website visited in Chrome Incognito
#   memory forensics test file       Unsaved text typed in Notepad:
#                                    "This is a memory forensics test
#                                     file - Abdul Ghafoor"
#   notepad.exe                      Notepad process was running in RAM
#   chrome.exe                       Chrome process was running in RAM
#   Projects.pdf                     PDF file that was open at dump time
SEARCH_TERMS = [
    b"safeshieldx",
    b"pinterest",
    b"memory forensics test file",
    b"notepad.exe",
    b"chrome.exe",
    b"Projects.pdf",
]

# Read the dump 1 MB at a time. A RAM dump is several gigabytes, so it
# must never be loaded into memory all at once.
CHUNK_SIZE = 1024 * 1024  # 1 MB

# Keep the last 200 bytes of each chunk and prepend them to the next one.
# Without this overlap, a keyword split across a chunk boundary
# (for example "safe" at the end of one chunk and "shieldx" at the
# start of the next) would be missed.
OVERLAP_SIZE = 200


# ---------------------------------------------------------------------------
# 2. CORE SEARCH — count every occurrence of every keyword in the dump
# ---------------------------------------------------------------------------

def count_terms_in_dump(dump_path, terms):
    """
    Count occurrences of each byte term in a binary dump file.

    Args:
        dump_path: Path to the .mem dump file.
        terms:     List of byte strings to search for.

    Returns:
        A dict mapping each term (bytes) to its total count (int).
    """
    # Start every counter at zero.
    counts = {term: 0 for term in terms}

    # "rb" = read in binary mode. Text mode would corrupt a RAM dump.
    with open(dump_path, "rb") as dump_file:
        buffer = b""  # Rolling buffer: overlap + current chunk

        while True:
            chunk = dump_file.read(CHUNK_SIZE)

            if not chunk:  # Empty read means end of file — stop.
                break

            buffer = buffer + chunk

            for term in terms:
                counts[term] += buffer.count(term)

            # Keep only the tail for the next round (see OVERLAP_SIZE).
            buffer = buffer[-OVERLAP_SIZE:]

    return counts


# ---------------------------------------------------------------------------
# 3. OUTPUT — print the results in the same format as the practical work
# ---------------------------------------------------------------------------

def print_results(counts):
    """Print one line per keyword, e.g.  'safeshieldx : 1849'."""
    for term, count in counts.items():
        print(f"{term.decode(errors='replace')} : {count}")


# ---------------------------------------------------------------------------
# 4. MAIN — choose the dump, check it exists, run the search
# ---------------------------------------------------------------------------

def main(argv=None):
    argv = sys.argv if argv is None else argv

    # If the user passed a path on the command line, use it.
    # Otherwise fall back to DEFAULT_PATH above.
    dump_path = argv[1] if len(argv) > 1 else DEFAULT_PATH
    path = Path(dump_path)

    if not path.is_file():
        print(f"Error: dump file not found:\n  {dump_path}")
        print("Check the path in DEFAULT_PATH, or pass the correct "
              "path as an argument to python search.py")
        return 1

    print(f"Searching: {dump_path}")
    counts = count_terms_in_dump(path, SEARCH_TERMS)
    print_results(counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
