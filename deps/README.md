# macTLS External Dependencies

This directory contains user-supplied third-party libraries that are NOT
included in the git repository due to redistribution restrictions.

## Required Files

| Filename | Description | Source | SHA256 |
|----------|-------------|--------|--------|
| `MSL_C_Carbon.Lib` | Metrowerks CodeWarrior MSL C library for Carbon (PPC) | User-supplied | `e4b54a96d9bd9b71bcae5324ece90750` |
| `MSL_Runtime_PPC_D.Lib` | Metrowerks CodeWarrior MSL Runtime library (PPC Debug) | User-supplied | `8cd3d599e47a501c0ce1ebb84628fa7c` |

## Placement

Place both files in this directory (`/home/patrick/Webs/macTLS/deps/`).

The build configuration references them via relative paths:
- `os9/macmake.toml`: `../deps/MSL_C_Carbon.Lib` and `../deps/MSL_Runtime_PPC_D.Lib`
- `macTLSProbe/macmake.toml`: `../../deps/MSL_C_Carbon.Lib` and `../../deps/MSL_Runtime_PPC_D.Lib`

## Redistribution Notice

MSL libraries are proprietary Metrowerks (CodeWarrior) software. They are
NOT included in this repository. Users must obtain them from their own
CodeWarrior installation and place them in `deps/` before building.

Without these files, the macTLSLib and macTLSProbe targets cannot link.
