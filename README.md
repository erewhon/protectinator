# protectinator

General Security tool

# Goals

I want this to a simple, run-anywhere network security tool. 

- Simple enough for anyone to use
- Zero configuration needed
- Minimal resource impact
- Desktops and servers
- One or more computers
- Ideally just one self-contained executable that can run without installing (on thumb drive for example)
- GUI and command line

# Architecture

Written in Rust for performance and security.
Minimal external dependencies beyond core Rust.

# Features

- Read Sigma rules (https://github.com/SigmaHQ/sigma) and check local machine, skipping rules that don't apply.  Can read repository of rules, plus individual local rule files
- Create SHA256 or higher checksum of all files recursively in a directory.  Can then verify the checksums at a future time to detect filesystem tampering
- Check system at network and OS level to see if system has reasonable settings
- Scan OS files and verify them against known good versions (stored in a file locally, on web site, or IPFS)
