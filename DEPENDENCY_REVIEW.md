# Dependency diagnostic review

Reviewed 2026-09-19 against the locked workspace at `07cfada` (full default
features, all target dependency paths). Owner: Codex/Tyler local maintenance.
Review deadline: **2026-10-19**, or before upstream submission if earlier.

`cargo deny --locked check` passes advisories, licenses, bans and sources.
The 30 duplicate-package warnings below remain visible: none is a redundant
patch release that Cargo can safely unify within the existing constraints.
Each row is temporarily accepted through the review deadline. Follow-up is
to evaluate the named parent migrations with workspace and platform tests;
do not override incompatible major or pre-1.0 minor requirements merely to
silence a diagnostic. This disposition does not waive future advisories.

The unused `OpenSSL` and `Unicode-DFS-2016` license allowances were removed.
Neither is encountered in the locked default-feature dependency graph across
targets, and fresh default/all-feature license checks pass without them. Future dependencies
using either license must receive an explicit policy review.

## Package dispositions

| Package             | Locked generations          | Reason retained / parent migration needed                                                                                               |
| ------------------- | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `block-buffer`      | 0.10.4, 0.12.1              | digest 0.10 (secret-service via hmac/sha2) and 0.11 (tungstenite via sha1) require incompatible buffer APIs.                            |
| `console`           | 0.15.11, 0.16.4             | better-panic 0.3 requires 0.15; dialoguer, indicatif and insta require 0.16.                                                            |
| `cpufeatures`       | 0.2.17, 0.3.0               | aes/sha2 require 0.2; chacha20/sha1 require 0.3.                                                                                        |
| `crypto-common`     | 0.1.7, 0.2.2                | cipher 0.4/digest 0.10 require 0.1; digest 0.11 requires 0.2.                                                                           |
| `darling`           | 0.21.3, 0.23.0, 0.24.0      | derive_setters requires 0.21, bon-macros 0.23, and instability 0.24.                                                                    |
| `darling_core`      | 0.21.3, 0.23.0, 0.24.0      | The three darling/darling_macro generations each require their matching core.                                                           |
| `darling_macro`     | 0.21.3, 0.23.0, 0.24.0      | The three darling generations each require their matching procedural macro.                                                             |
| `digest`            | 0.10.7, 0.11.3              | hmac/sha2 in secret-service require 0.10; sha1 in tungstenite requires 0.11.                                                            |
| `getrandom`         | 0.2.17, 0.4.3               | ring, secret-service and rand_core 0.6 require 0.2; current rand, tempfile, uuid and quinn require 0.4.                                 |
| `hashbrown`         | 0.14.5, 0.16.1, 0.17.1      | dashmap requires 0.14, kasuari 0.16, and indexmap/lru/ratatui 0.17.                                                                     |
| `linux-raw-sys`     | 0.4.15, 0.12.1              | rustix 0.38 requires 0.4; rustix 1 requires 0.12.                                                                                       |
| `rand`              | 0.8.7, 0.9.5, 0.10.2        | ratatui-image requires 0.8; quantette 0.9; tungstenite and quinn-proto 0.10.                                                            |
| `rand_core`         | 0.6.4, 0.9.5, 0.10.1        | rand 0.8/rand_chacha, rand 0.9/rand_xoshiro and rand 0.10/chacha20 each require their corresponding core generation.                    |
| `rustix`            | 0.38.44, 1.1.4              | ratatui-image requires 0.38; crossterm, tempfile, terminal_size and Linux async/keyring dependencies require 1.                         |
| `serde_spanned`     | 0.6.9, 1.1.1                | toml 0.8/toml_edit 0.22 require 0.6; toml 1.1 requires 1.                                                                               |
| `syn`               | 2.0.119, 3.0.3              | darling 0.21/0.23, zbus macros and other procedural macros require 2; serde/clap/tokio derives, darling 0.24 and thiserror 2 require 3. |
| `thiserror`         | 1.0.69, 2.0.19              | ratatui-image requires 1; UniFly, opaline, tachyonfx, tungstenite and quinn require 2.                                                  |
| `thiserror-impl`    | 1.0.69, 2.0.19              | Each thiserror major requires its matching procedural macro implementation.                                                             |
| `toml`              | 0.8.23, 1.1.4+spec-1.1.0    | figment and opaline require 0.8; UniFly and human-panic require 1.1.                                                                    |
| `toml_datetime`     | 0.6.11, 1.1.1+spec-1.1.0    | toml 0.8/toml_edit 0.22 require 0.6; toml 1.1/toml_edit 0.25 require 1.1.                                                               |
| `toml_edit`         | 0.22.27, 0.25.13+spec-1.1.0 | toml 0.8 requires 0.22; proc-macro-crate requires 0.25.                                                                                 |
| `unicode-width`     | 0.1.14, 0.2.2               | miette requires 0.1; current terminal, table and TUI consumers require 0.2.                                                             |
| `windows`           | 0.58.0, 0.62.2              | ratatui-image requires 0.58; sysinfo via human-panic requires 0.62.                                                                     |
| `windows-core`      | 0.58.0, 0.62.2              | windows 0.58 requires 0.58; windows 0.62 and iana-time-zone require 0.62.                                                               |
| `windows-implement` | 0.58.0, 0.60.2              | windows-core 0.58 requires 0.58; windows-core 0.62 requires 0.60.                                                                       |
| `windows-interface` | 0.58.0, 0.59.3              | windows-core 0.58 requires 0.58; windows-core 0.62 requires 0.59.                                                                       |
| `windows-result`    | 0.2.0, 0.4.1                | windows-core 0.58/windows-strings 0.1 require 0.2; windows-core 0.62 requires 0.4.                                                      |
| `windows-strings`   | 0.1.0, 0.5.1                | windows-core 0.58 requires 0.1; windows-core 0.62 requires 0.5.                                                                         |
| `windows-sys`       | 0.52.0, 0.59.0, 0.61.2      | ring requires 0.52; console 0.15/rtoolbox/rustix 0.38 require 0.59; current networking, terminal and keyring consumers require 0.61.    |
| `winnow`            | 0.7.15, 1.0.4               | toml_edit 0.22 requires 0.7; current toml, toml_edit and zbus/zvariant require 1.                                                       |

## Reproduction and scope

```sh
cargo deny --locked check
cargo deny --locked --all-features check licenses
cargo tree --locked --duplicates --target all
```

Inspect individual parents with `cargo tree --locked --target all --invert
<name>@<version>`. The all-target graph includes Linux secret-service and
Windows bindings even on macOS; it is dependency evidence, not proof that the
application runs on those platforms. Cargo may also print repeated packages
with the **same** version for distinct feature/build contexts, and the
`webpki-roots` compatibility shim forwards its older API to the new package;
those are not additional cargo-deny duplicate warnings.

The checked-in Rust minimum remains 1.94. Dependency maintenance must preserve
that minimum and the full CLI/TUI default features. Runtime platform results
belong in the contribution validation record, separate from this dependency
policy disposition.
