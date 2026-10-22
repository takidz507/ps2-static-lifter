# NOTICE — provenance and licensing

## Target binaries (`targets/`)

- `hello_kernel_min.elf` — a synthetic ELF authored for this project,
  mirroring the structure of the official ps2sdk minimal kernel sample
  (ps2sdk commit `329e2bb`). Original to this project.
- `hello_real.elf`, `graph.elf` — built by the project from the official
  **ps2dev / ps2sdk** sample sources using the official ps2dev toolchain
  (ee-gcc 15.2.0). ps2sdk is a community open-source project; its code is
  distributed under its own license terms (see the ps2sdk repository,
  https://github.com/ps2dev/ps2sdk). The samples are included here so every
  measurement in this repository can be reproduced exactly.

## Software referenced but not redistributed here

- **500 Card Game (PS2 homebrew)** by khant735 —
  https://github.com/khant735/500-Card-Game-PS2 — the game binary was
  obtained from the author's own public release (v501B) for analysis. It is
  not included in this repository; download it from the author.
- **Open PS2 Loader (OPL)** by the ps2homebrew community — analyzed in
  binary form only (the official v1.1.0 release was found to be a
  ps2-packer–packed envelope); no OPL code is included here.

## This project's own code

The analyzer, lifter, runtime model, host runners, tests, Android apps,
specifications, and documents in this repository were produced for this
project by its credited contributors (see README → Credits). A formal
open-source license for this code has not been chosen yet by the repository
owner; until one is added, all rights are reserved by the owner. The
*measurements and reports* are published for study and reproduction.

## Trademarks

PlayStation and PS2 are trademarks of Sony Interactive Entertainment. This
is an independent, non-commercial research project, not affiliated with or
endorsed by Sony. No Sony code, BIOS, or commercial game data is included
or used.
