# Memory Forensics: Analysing RAM for Digital Evidence

A practical memory forensics project that proves what lives in RAM — even data that was never saved to disk.

**Author:** Abdul Ghafoor — BS Cyber Security & Digital Forensics, The Islamia University of Bahawalpur
**Course:** Introduction to Digital Forensics — Topic 15, Memory Forensics
**Tools:** FTK Imager 8.3.0.27, Python 3.11.9, Volatility 3 (2.28.3), Autopsy 4.23.1

## What I did

1. Set up a controlled test on my own laptop: unsaved text in Notepad, a website visited in Chrome Incognito, and an open PDF.
2. Captured the full RAM with FTK Imager and hashed the dump (SHA-256) to prove integrity.
3. Searched the dump with `search.py` — a Python tool that reads a multi-gigabyte `.mem` file in 1 MB chunks with a 200-byte overlap, so no keyword split across a chunk boundary is missed.
4. Captured a second dump after a full power-off and restart, and compared the counts to prove RAM is volatile.

## What I found

| Term | Before power-off | After power-off |
|---|---:|---:|
| safeshieldx | 1,849 | 9,410* |
| pinterest | 4,429 | 4,224 |
| memory forensics test file | 3 | 4 |
| notepad.exe | 32 | 177 |
| chrome.exe | 198 | 918 |
| Projects.pdf | 2 | 1 |

\* Browser terms can still appear after restart because Windows and Chrome restore / cache data. The unsaved Notepad text and the open PDF fall to almost zero — that is the volatility proof.

Run 1 (19.6 GB dump) showed the same pattern more clearly: `pinterest` fell 79% (37,670 → 7,863) and the unsaved test text fell 72% (153 → 43) after power-off.

**Key point:** a count proves a term was present in RAM. It does not, by itself, prove the exact page or action — that needs a deeper Volatility / timeline analysis.

## What did not work — and why it is in here

- **Volatility 3:** `windows.pslist` / `windows.info` failed — the symbol-table download was reset by the connection. Documented, not hidden.
- **Autopsy 4.23.1:** cannot open a `.mem` file — it expects a disk image, not RAM. Documented, not hidden.

Honest failures are part of the result.

## How to run it

```powershell
python search.py "D:\Forensics\MemoryForensics\dump\memory-test-2.mem"
```

No extra libraries needed — Python standard library only. Pass a dump path as an argument, or edit `DEFAULT_PATH` in the script.

## Ethics

This tool was used only on my own laptop, on my own test data. No other person's computer, account, or data was accessed. No password was collected, used, or displayed.

RAM dumps are **not** included in this repository — they are gigabytes in size and contain personal data. The SHA-256 hashes of the dumps are recorded in the full project report.

## Files

- `search.py` — the RAM dump keyword search tool
- `README.md` — this file

The full 15-page project report (PDF) and presentation are part of the university submission, due 1 December 2026.
