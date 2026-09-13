# slh-dsa-hw (ESP32-S3 hardware-accelerated fork of `slh-dsa`)

This is a local fork of RustCrypto's [`slh-dsa`] crate, modified to add an ESP32-S3 hardware SHA-256/SHA-512 acceleration backend (the `hw-sha` Cargo feature) for use by this repository's `nano-signer` firmware. It is **not** RustCrypto's own crate, is not published to crates.io under this name, and is not affiliated with or endorsed by the RustCrypto project. 

Original crate: <https://github.com/RustCrypto/signatures/tree/master/slh-dsa> (pure Rust implementation of SLH-DSA, aka SPHINCS+, per the [FIPS-205 Standard]).

## What changed from upstream

- `src/hashes/hw.rs` (new file): hardware SHA-256/SHA-512 backend for the ESP32-S3 SHA peripheral.
- `src/hashes/sha2.rs`: added hardware-backed variants of `Sha2L1` and `Sha2L35`, feature-gated behind `hw-sha`, alongside the original (unmodified) software implementations.
- `src/hashes.rs`: wires in the `hw` module and re-exports `init_hw_sha`.
- `Cargo.toml`: added the `hw-sha` feature and its optional `esp-hal`/`critical-section`/`nb` dependencies.

Everything else in `src/` is unmodified from upstream `slh-dsa 0.2.0-rc.5`.

`Cargo.toml`'s `[package] name` is `"slh-dsa-hw"`, renamed from the vendored `"slh-dsa"` so this fork no longer shadows the upstream crate's name. `nano-signer` depends on it via `path = "../slh-dsa-hw"` and imports it as `slh_dsa_hw`.

## Design notes

The source comments in `src/hashes/hw.rs` and `src/hashes/sha2.rs` are kept short and point back here for the reasoning; this section is where that reasoning actually lives.

**Scope.** Both `Sha2L1` (128s/128f) and `Sha2L35` (192s/192f/256s/256f) are fully hardware-backed under `hw-sha`, including `prf_msg`/`h_msg`. Those two were initially left on software, on the assumption that running once per signature made their cost negligible; that was wrong; their cost scales with the signed message's length, not their call count, and became the dominant cost once everything else got faster. `prf_msg` is HMAC, and esp-hal has no hardware HMAC wrapper, so it's a hand-rolled `H((K^opad) || H((K^ipad) || message))` construction around the hardware SHA-256/512 primitive. This is only correct because every HMAC key here (`sk_prf`) is at most 32 bytes, always shorter than either hash's block size; the "hash an over-long key down first" case in the full HMAC spec is not implemented, since it never applies.

**The SHA peripheral is a singleton**, so it lives in one global `critical_section`-guarded static (`hw.rs`) rather than being threaded through `HashSuite`'s `&self` methods. [`init_hw_sha`] must be called once at boot with the driver from `esp_hal::init()`'s `Peripherals`; every hardware-backed method panics with a clear message if that never happened, rather than silently doing something else.

**Prefixes are re-hashed per call, not cached as peripheral state.** Every `f`/`h`/`t`/`prf_sk` call starts with the same `pk_seed`-derived block; the software suite caches that as a `Sha256`/`Sha512` midstate and `.clone()`s it per call. An earlier revision of this fork tried the hardware equivalent, `esp_hal::sha::Context`'s save/restore support, and it doesn't work: `Context<A>` derives `Clone`/`Debug`, which adds an `A: Clone`/`A: Debug` bound on the generic parameter itself regardless of whether the type actually needs it, and esp-hal's `Sha256`/`Sha512` marker types never implement either. `Context<Sha256>: Clone` is unsatisfiable for any real algorithm. This was only caught by a real build against the actual target; the API looks correct from reading the source alone. The prefix is now stored as plain bytes and re-hashed from scratch on every call via a fresh `ShaDigest`, giving up that one optimization while keeping everything else on hardware.

**Digests are always taken at full length and truncated in Rust**, never via the peripheral's "short hash" option (requesting fewer bytes than the full digest). There was no way to verify in this environment that a hardware short digest is bit-identical to a full digest truncated by hand; getting that wrong would silently produce wrong signatures, so this doesn't rely on it.

**A lifetime gotcha in `hw_hmac_sha256`/`hw_hmac_sha512`:** don't build the HMAC inner hash by chaining a function-local buffer (`ipad`) onto the `parts` parameter with `.chain()`. `parts`'s type carries the function's own generic lifetime, which the *caller* controls and could be `'static`; `.chain()` needs both sides to share one concrete `Item` type, which would require the borrow checker to prove a local stack array outlives an arbitrary external lifetime, which it can't. Feed the local buffer and `parts` to the hasher as two separate steps instead (see how `HwPrefix256::hash` already does this for its own cached-prefix-plus-parts case).

[`init_hw_sha`]: src/hashes/hw.rs

## ⚠️ Security Warning

The upstream implementation has never been independently audited. The hardware-acceleration changes in this fork have not been audited either, and have received considerably less scrutiny than upstream's own code. **Use at your own risk**, more so than you would with unmodified RustCrypto crates.

## License

Unmodified from upstream. All code in this crate, including the modifications listed above, is licensed under either of:

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](https://opensource.org/licenses/MIT)

at your option. Original copyright: Trail of Bits, 2024 (see `LICENSE-APACHE`/`LICENSE-MIT`).

[`slh-dsa`]: https://github.com/RustCrypto/signatures/tree/master/slh-dsa
[FIPS-205 Standard]: https://csrc.nist.gov/pubs/fips/205/final
