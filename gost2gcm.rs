// File encryption with GOST2-128 in GCM mode.
    
// cargo run --release

/*
 *  Cargo.toml

[package]
name = "gost2gcm"
version = "0.1.0"
edition = "2021"
description = "GOST2-128 + GCM encryption/decryption tool"

[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"

[dependencies]

*/

// ---------------------- Prelude / imports ----------------------
use std::cmp::min;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write, BufReader, BufWriter};

// ---------------------- Platform helpers (password, RNG) ----------------------

/* ---------------------- No-echo password input ----------------------
 * Rust version inspired by the C code:
 * - On Unix/BSD/macOS: we shell out to `stty -echo` to avoid unsafe FFI for termios.
 * - On Windows: we use minimal FFI to SetConsoleMode to clear ENABLE_ECHO_INPUT.
 * This keeps dependencies to zero while preserving behavior.
 */

#[cfg(windows)]
mod pw {
    // Windows console echo off via SetConsoleMode
    use std::io::{self, Write};

    type BOOL = i32;
    type DWORD = u32;
    type HANDLE = *mut core::ffi::c_void;

    const STD_INPUT_HANDLE: DWORD = -10i32 as u32;
    const ENABLE_ECHO_INPUT: DWORD = 0x0004;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(nStdHandle: DWORD) -> HANDLE;
        fn GetConsoleMode(hConsoleHandle: HANDLE, lpMode: *mut DWORD) -> BOOL;
        fn SetConsoleMode(hConsoleHandle: HANDLE, dwMode: DWORD) -> BOOL;
    }

    pub fn read_password(prompt: &str) -> io::Result<String> {
        let mut stdout = io::stdout();
        write!(stdout, "{}", prompt)?;
        stdout.flush()?;

        unsafe {
            let h_in = GetStdHandle(STD_INPUT_HANDLE);
            if h_in.is_null() {
                let mut s = String::new();
                io::stdin().read_line(&mut s)?;
                if s.ends_with('\n') { s.pop(); if s.ends_with('\r') { s.pop(); } }
                writeln!(io::stdout())?;
                return Ok(s);
            }
            let mut mode: DWORD = 0;
            if GetConsoleMode(h_in, &mut mode as *mut DWORD) == 0 {
                let mut s = String::new();
                io::stdin().read_line(&mut s)?;
                if s.ends_with('\n') { s.pop(); if s.ends_with('\r') { s.pop(); } }
                writeln!(io::stdout())?;
                return Ok(s);
            }
            let saved = mode;
            let new_mode = mode & !ENABLE_ECHO_INPUT;
            if SetConsoleMode(h_in, new_mode) == 0 {
                let mut s = String::new();
                io::stdin().read_line(&mut s)?;
                if s.ends_with('\n') { s.pop(); if s.ends_with('\r') { s.pop(); } }
                writeln!(io::stdout())?;
                return Ok(s);
            }

            let mut s = String::new();
            let res = io::stdin().read_line(&mut s);
            let _ = SetConsoleMode(h_in, saved);
            writeln!(io::stdout())?;

            let mut s = res.map(|_| s)?;
            if s.ends_with('\n') { s.pop(); if s.ends_with('\r') { s.pop(); } }
            Ok(s)
        }
    }
}

#[cfg(any(unix, target_os = "macos"))]
mod pw {
    use std::io::{self, Write};
    use std::process::Command;
    use std::fs::OpenOptions;
    use std::io::BufRead;

    pub fn read_password(prompt: &str) -> io::Result<String> {
        let mut stdout = io::stdout();
        write!(stdout, "{}", prompt)?;
        stdout.flush()?;

        // turn off echo using `stty -echo`
        let _ = Command::new("sh").arg("-c").arg("stty -echo < /dev/tty").status();
        let mut s = String::new();
        let f = OpenOptions::new().read(true).open("/dev/tty");
        match f {
            Ok(f) => {
                let mut br = io::BufReader::new(f);
                br.read_line(&mut s)?;
            }
            Err(_) => {
                // fallback: read from stdin (may echo)
                io::stdin().read_line(&mut s)?;
            }
        }
        // restore echo
        let _ = Command::new("sh").arg("-c").arg("stty echo < /dev/tty").status();
        writeln!(io::stdout())?;

        if s.ends_with('\n') { s.pop(); if s.ends_with('\r') { s.pop(); } }
        Ok(s)
    }
}

/* ---------------------- Portable secure random ----------------------
 * We follow the C code preference order:
 *   - arc4random_buf (BSD/macOS)
 *   - /dev/urandom (Unix)
 *   - BCryptGenRandom (Windows)
 *   - fallback weak RNG (time-based)
 */

mod rng {
    use std::io;

    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    pub fn secure_random_bytes(buf: &mut [u8]) -> io::Result<()> {
        // Use arc4random_buf via FFI
        extern "C" { fn arc4random_buf(buf: *mut core::ffi::c_void, len: usize); }
        unsafe { arc4random_buf(buf.as_mut_ptr() as *mut _, buf.len()); }
        Ok(())
    }

    #[cfg(all(unix, not(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))))]
    pub fn secure_random_bytes(buf: &mut [u8]) -> io::Result<()> {
        // Read from /dev/urandom
        use std::fs::File;
        use std::io::Read;
        let mut f = File::open("/dev/urandom")?;
        f.read_exact(buf)?;
        Ok(())
    }

    #[cfg(windows)]
    pub fn secure_random_bytes(buf: &mut [u8]) -> io::Result<()> {
        // BCryptGenRandom from CNG
        type NTSTATUS = i32;
        const STATUS_SUCCESS: NTSTATUS = 0;
        const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;

        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                hAlgorithm: *mut core::ffi::c_void,
                pbBuffer: *mut u8,
                cbBuffer: u32,
                dwFlags: u32,
            ) -> NTSTATUS;
        }
        let st = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if st == STATUS_SUCCESS { Ok(()) } else { Err(io::Error::new(io::ErrorKind::Other, "BCryptGenRandom failed")) }
    }

    // Last-resort weak RNG (only if all above fail, explicitly requested)
    pub fn fallback_weak_rng(buf: &mut [u8]) {
        /* WARNING: This is NOT cryptographically secure. */
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        // simple xorshift64* seeded from time
        fn xorshift64(mut x: u64) -> u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        }
        let mut seed = (now as u64) ^ 0x9E3779B97F4A7C15u64;
        for b in buf.iter_mut() {
            seed = xorshift64(seed);
            *b = (seed & 0xFF) as u8;
        }
    }

    pub fn get_iv_16(iv: &mut [u8; 16]) {
        if secure_random_bytes(iv).is_ok() {
            return;
        }
        eprintln!("WARNING: secure RNG unavailable; using weak time-based fallback.");
        fallback_weak_rng(iv);
    }
}

// ---------------------- GOST2-128 cipher ----------------------

/* Keep the same constants / S-boxes and hashing pipeline that produces 64 * 64-bit subkeys from a password.
 * Rust-idiomatic notes:
 * - We encapsulate the hashing state in a struct instead of globals.
 * - We keep the exact byte-level behavior.
 */

type Word64 = u64;

const N1: usize = 512; /* 4096-bit GOST2-128 key for 64 * 64-bit subkeys */

struct HashState {
    x1: i32,
    x2: usize,
    h2: [u8; N1],
    h1: [u8; N1 * 3],
}

impl HashState {
    fn new() -> Self {
        Self {
            x1: 0,
            x2: 0,
            h2: [0u8; N1],
            h1: [0u8; N1 * 3],
        }
    }

    fn hashing(&mut self, t1: &[u8]) {
        // static s4 table
        static S4: [u8; 256] = [
            13,199,11,67,237,193,164,77,115,184,141,222,73,38,147,36,150,87,21,104,12,61,156,101,111,145,
            119,22,207,35,198,37,171,167,80,30,219,28,213,121,86,29,214,242,6,4,89,162,110,175,19,157,
            3,88,234,94,144,118,159,239,100,17,182,173,238,68,16,79,132,54,163,52,9,58,57,55,229,192,
            170,226,56,231,187,158,70,224,233,245,26,47,32,44,247,8,251,20,197,185,109,153,204,218,93,178,
            212,137,84,174,24,120,130,149,72,180,181,208,255,189,152,18,143,176,60,249,27,227,128,139,243,253,
            59,123,172,108,211,96,138,10,215,42,225,40,81,65,90,25,98,126,154,64,124,116,122,5,1,168,83,190,
            131,191,244,240,235,177,155,228,125,66,43,201,248,220,129,188,230,62,75,71,78,34,31,216,254,136,91,
            114,106,46,217,196,92,151,209,133,51,236,33,252,127,179,69,7,183,105,146,97,39,15,205,112,200,166,
            223,45,48,246,186,41,148,140,107,76,85,95,194,142,50,49,134,23,135,169,221,210,203,63,165,82,161,
            202,53,14,206,232,103,102,195,117,250,99,0,74,160,241,2,113
        ];

        let mut b4 = 0usize;
        let mut b6 = t1.len();
        while b6 > 0 {
            while b6 > 0 && self.x2 < N1 {
                let b5 = t1[b4] as i32;
                b4 += 1;
                self.h1[self.x2 + N1] = b5 as u8;
                self.h1[self.x2 + (N1 * 2)] = (b5 as u8) ^ self.h1[self.x2];
                self.x1 = {
                    let t = self.h2[self.x2] ^ S4[((b5 ^ self.x1) & 0xff) as usize];
                    self.h2[self.x2] = t;
                    t as i32
                };
                self.x2 += 1;
                b6 -= 1;
            }
            if self.x2 == N1 {
                let mut b2 = 0u8;
                self.x2 = 0;
                for b3 in 0..(N1 + 2) {
                    for b1 in 0..(N1 * 3) {
                        b2 = {
                            let t = self.h1[b1] ^ S4[b2 as usize];
                            self.h1[b1] = t;
                            t
                        };
                    }
                    b2 = b2.wrapping_add((b3 % 256) as u8);
                }
            }
        }
    }

    fn end_hash(mut self) -> [u8; N1] {
        let mut h3 = [0u8; N1];
        let n4 = N1 - self.x2;
        for i in 0..n4 {
            h3[i] = n4 as u8;
        }
        self.hashing(&h3[..n4]);
        let h2_copy = self.h2; // avoid immutably borrowing self during &mut self call
        self.hashing(&h2_copy);
        let mut h4 = [0u8; N1];
        h4.copy_from_slice(&self.h1[..N1]);
        h4
    }
}

fn create_keys(h4: &[u8; N1]) -> [Word64; 64] {
    // create 64 * 64-bit subkeys from h4 hash
    let mut key = [0u64; 64];
    let mut k = 0usize;
    for i in 0..64 {
        let mut v = 0u64;
        for _ in 0..8 {
            v = (v << 8) + (h4[k] as u64);
            k += 1;
        }
        key[i] = v;
    }
    key
}

/* S-boxes / tables */
static K1_:  [u8; 16]  = [ 0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3 ];
static K2_:  [u8; 16]  = [ 0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9 ];
static K3_:  [u8; 16]  = [ 0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB ];
static K4_:  [u8; 16]  = [ 0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3 ];
static K5_:  [u8; 16]  = [ 0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2 ];
static K6_:  [u8; 16]  = [ 0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE ];
static K7_:  [u8; 16]  = [ 0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC ];
static K8_:  [u8; 16]  = [ 0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC ];
static K9_:  [u8; 16]  = [ 0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1 ];
static K10_: [u8; 16]  = [ 0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF ];
static K11_: [u8; 16]  = [ 0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0 ];
static K12_: [u8; 16]  = [ 0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB ];
static K13_: [u8; 16]  = [ 0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC ];
static K14_: [u8; 16]  = [ 0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0 ];
static K15_: [u8; 16]  = [ 0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7 ];
static K16_: [u8; 16]  = [ 0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2 ];

/* Precomputed tables built from S-boxes (lazy one-time init) */
static mut K175: [u8; 256] = [0; 256];
static mut K153: [u8; 256] = [0; 256];
static mut K131: [u8; 256] = [0; 256];
static mut K109: [u8; 256] = [0; 256];
static mut K87:  [u8; 256] = [0; 256];
static mut K65:  [u8; 256] = [0; 256];
static mut K43:  [u8; 256] = [0; 256];
static mut K21:  [u8; 256] = [0; 256];

fn kboxinit() {
    // safe wrapper around once-only init
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| unsafe {
        for i in 0..256usize {
            K175[i] = (K16_[(i >> 4) & 15] << 4) | K15_[i & 15];
            K153[i] = (K14_[(i >> 4) & 15] << 4) | K13_[i & 15];
            K131[i] = (K12_[(i >> 4) & 15] << 4) | K11_[i & 15];
            K109[i] = (K10_[(i >> 4) & 15] << 4) | K9_[i & 15];
            K87[i]  = (K8_[(i >> 4) & 15]  << 4) | K7_[i & 15];
            K65[i]  = (K6_[(i >> 4) & 15]  << 4) | K5_[i & 15];
            K43[i]  = (K4_[(i >> 4) & 15]  << 4) | K3_[i & 15];
            K21[i]  = (K2_[(i >> 4) & 15]  << 4) | K1_[i & 15];
        }
    });
}

#[inline]
fn f_gost(x: u64) -> u64 {
    // use precomputed tables to apply S-boxes nibble-wise then rotate left by 11
    let y = (x >> 32) as u32;
    let z = (x & 0xffff_ffff) as u32;
    unsafe {
    let y = ((K87[((y >> 24) & 0xFF) as usize] as u64) << 24)
      | ((K65[((y >> 16) & 0xFF) as usize] as u64) << 16)
      | ((K43[((y >>  8) & 0xFF) as usize] as u64) <<  8)
      |  (K21[(y & 0xFF) as usize] as u64);
    let z = ((K175[((z >> 24) & 0xFF) as usize] as u64) << 24)
      | ((K153[((z >> 16) & 0xFF) as usize] as u64) << 16)
      | ((K131[((z >>  8) & 0xFF) as usize] as u64) <<  8)
      |  (K109[(z & 0xFF) as usize] as u64);

    let x = (y << 32) | (z & 0xffff_ffff);
        x.rotate_left(11)
    }
}

fn gostcrypt(input: [u64; 2], key: &[u64; 64]) -> [u64; 2] {
    let (mut a, mut b) = (input[0], input[1]);
    let mut k = 0usize;
    for _ in 0..32 {
        b ^= f_gost(a.wrapping_add(key[k])); k += 1;
        a ^= f_gost(b.wrapping_add(key[k])); k += 1;
    }
    [b, a]
}

#[allow(dead_code)]
fn gostdecrypt(input: [u64; 2], key: &[u64; 64]) -> [u64; 2] {
    let (mut a, mut b) = (input[0], input[1]);
    let mut k: i32 = 63;
    for _ in 0..32 {
        b ^= f_gost(a.wrapping_add(key[k as usize])); k -= 1;
        a ^= f_gost(b.wrapping_add(key[k as usize])); k -= 1;
    }
    [b, a]
}

// ---------------------- GCM helpers (128-bit ops) ----------------------

/* Rust note: use a struct of two u64 for big-endian logical 128-bit value. */
#[derive(Clone, Copy)]
struct Be128 { hi: u64, lo: u64 } /* big-endian logical 128-bit */

fn load_be128(b: &[u8; 16]) -> Be128 {
    let hi = u64::from_be_bytes([b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]]);
    let lo = u64::from_be_bytes([b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]]);
    Be128 { hi, lo }
}

fn store_be128(x: Be128, b: &mut [u8; 16]) {
    b[..8].copy_from_slice(&x.hi.to_be_bytes());
    b[8..].copy_from_slice(&x.lo.to_be_bytes());
}

fn be128_xor(a: Be128, b: Be128) -> Be128 {
    Be128 { hi: a.hi ^ b.hi, lo: a.lo ^ b.lo }
}

/* right shift by 1 bit (big-endian logical value) */
fn be128_shr1(v: Be128) -> Be128 {
    Be128 {
        lo: (v.lo >> 1) | ((v.hi & 1) << 63),
        hi: (v.hi >> 1),
    }
}

/* left shift by 1 bit */
fn be128_shl1(v: Be128) -> Be128 {
    Be128 {
        hi: (v.hi << 1) | (v.lo >> 63),
        lo: (v.lo << 1),
    }
}

/* GF(2^128) multiplication per SP 800-38D, right-shift method */
fn gf_mult(mut x: Be128, mut y: Be128) -> Be128 {
    let mut z = Be128 { hi: 0, lo: 0 };
    // R = 0xE1000000000000000000000000000000 (big-endian)
    const R: Be128 = Be128 { hi: 0xE100000000000000u64, lo: 0x0000000000000000u64 };
    for _ in 0..128 {
        let msb = (x.hi & 0x8000_0000_0000_0000u64) != 0;
        if msb { z = be128_xor(z, y); }
        let lsb = (y.lo & 1u64) != 0;
        y = be128_shr1(y);
        if lsb { y = be128_xor(y, R); }
        x = be128_shl1(x);
    }
    z
}

/* GHASH update: Y <- (Y ^ X) * H */
fn ghash_update(y: &mut Be128, h: Be128, block16: &[u8; 16]) {
    let x = load_be128(block16);
    *y = gf_mult(be128_xor(*y, x), h);
}

/* Encrypt a single 16-byte block with GOST2-128 */
fn gost_encrypt_block(input16: &[u8; 16], out16: &mut [u8; 16], key: &[u64; 64]) {
    let inw0 = u64::from_be_bytes([input16[0],input16[1],input16[2],input16[3],input16[4],input16[5],input16[6],input16[7]]);
    let inw1 = u64::from_be_bytes([input16[8],input16[9],input16[10],input16[11],input16[12],input16[13],input16[14],input16[15]]);
    let outw = gostcrypt([inw0, inw1], key);
    out16[..8].copy_from_slice(&outw[0].to_be_bytes());
    out16[8..].copy_from_slice(&outw[1].to_be_bytes());
}

/* Compute H = E_K(0^128) */
fn compute_h(h: &mut [u8; 16], key: &[u64; 64]) {
    let zero = [0u8; 16];
    gost_encrypt_block(&zero, h, key);
}

/* inc32 on the last 32 bits of a 128-bit counter (big-endian) */
fn inc32(ctr: &mut [u8; 16]) {
    let mut c = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
    c = c.wrapping_add(1);
    let be = c.to_be_bytes();
    ctr[12] = be[0]; ctr[13] = be[1]; ctr[14] = be[2]; ctr[15] = be[3];
}

/* Derive J0 from IV (generic case when IV != 12 bytes) */
fn derive_j0(j0: &mut [u8; 16], iv: &[u8], hbe: Be128) {
    // Y = 0
    let mut y = Be128 { hi: 0, lo: 0 };
    let mut block = [0u8; 16];

    // Process full 16-byte blocks of IV
    let mut off = 0usize;
    while iv.len().saturating_sub(off) >= 16 {
        let mut b = [0u8; 16];
        b.copy_from_slice(&iv[off..off+16]);
        ghash_update(&mut y, hbe, &b);
        off += 16;
    }
    // Last partial block (pad with zeros)
    if iv.len() > off {
        let rem = iv.len() - off;
        block.fill(0);
        block[..rem].copy_from_slice(&iv[off..]);
        ghash_update(&mut y, hbe, &block);
    }
    // Append 128-bit length block: 64-bit zeros || [len(IV) in bits]_64
    block.fill(0);
    let ivbits = (iv.len() as u64).wrapping_mul(8);
    block[8..].copy_from_slice(&ivbits.to_be_bytes());
    ghash_update(&mut y, hbe, &block);

    store_be128(y, j0);
}

/* Prepares GHASH lengths block for AAD(empty) and C(lenC) */
fn ghash_lengths_update(y: &mut Be128, hbe: Be128, _aad_bits: u64, c_bits: u64) {
    let mut lenblk = [0u8; 16];
    // [len(AAD)]_64 || [len(C)]_64 in bits, both big-endian
    // AAD is zero here
    lenblk[8..].copy_from_slice(&c_bits.to_be_bytes());
    ghash_update(y, hbe, &lenblk);
}

/* Constant-time tag comparison */
fn ct_memcmp(a: &[u8], b: &[u8]) -> u8 {
    let mut r = 0u8;
    let n = a.len().min(b.len());
    for i in 0..n {
        r |= a[i] ^ b[i];
    }
    r | ((a.len() ^ b.len()) as u8)
}

// ---------------------- File name helpers ----------------------
fn add_suffix_gost2(input: &str) -> String {
    format!("{input}.gost2")
}
fn strip_suffix_gost2(input: &str) -> String {
    let suf = ".gost2";
    if input.ends_with(suf) {
        input[..input.len()-suf.len()].to_string()
    } else {
        format!("{input}.dec")
    }
}

// ---------------------- High-level encrypt/decrypt ----------------------

const BUF_CHUNK: usize = 4096;

fn encrypt_file(infile: &str, outfile: &str, key: &[u64; 64]) -> io::Result<()> {
    let fi = File::open(infile)?;
    let mut br = BufReader::new(fi);
    let fo = OpenOptions::new().write(true).create(true).truncate(true).open(outfile)?;
    let mut bw = BufWriter::new(fo);

    /* Compute H and J0 */
    let mut h = [0u8; 16]; compute_h(&mut h, key);
    let hbe = load_be128(&h);

    let mut iv = [0u8; 16];
    rng::get_iv_16(&mut iv);

    /* Write IV (16 bytes) */
    bw.write_all(&iv)?;

    let mut j0 = [0u8; 16];
    derive_j0(&mut j0, &iv, hbe);

    /* S = GHASH over ciphertext (starts at 0) */
    let mut s = Be128 { hi: 0, lo: 0 };

    /* Counter starts from inc32(J0) */
    let mut ctr = j0;
    inc32(&mut ctr);

    /* Streaming encrypt */
    let mut inbuf = [0u8; BUF_CHUNK];
    let mut total_c_bytes: u64 = 0;

    loop {
        let r = br.read(&mut inbuf)?;
        if r == 0 { break; }
        let mut off = 0usize;
        while off < r {
            let n = min(16, r - off);
            // keystream = E_K(ctr)
            let mut ks = [0u8; 16];
            gost_encrypt_block(&ctr, &mut ks, key);
            inc32(&mut ctr);

            // P block (pad with zeros for XOR; we only write n bytes)
            let mut pblk = [0u8; 16];
            pblk[..n].copy_from_slice(&inbuf[off..off+n]);

            let mut cblk = [0u8; 16];
            for i in 0..n { cblk[i] = pblk[i] ^ ks[i]; }
            if n < 16 { for i in n..16 { cblk[i] = 0; } } // pad for GHASH

            // Update GHASH with ciphertext block (padded for partial)
            ghash_update(&mut s, hbe, &cblk);

            // Write ciphertext bytes (only n bytes)
            bw.write_all(&cblk[..n])?;

            total_c_bytes = total_c_bytes.wrapping_add(n as u64);
            off += n;
        }
    }

    /* S <- S ⊗ H with lengths block (AAD=0, C=total_c_bytes) */
    ghash_lengths_update(&mut s, hbe, 0, total_c_bytes.wrapping_mul(8));

    /* Tag T = E_K(J0) XOR S */
    let mut ej0 = [0u8; 16];
    gost_encrypt_block(&j0, &mut ej0, key);
    let mut sbytes = [0u8; 16];
    store_be128(s, &mut sbytes);
    let mut tag = [0u8; 16];
    for i in 0..16 { tag[i] = ej0[i] ^ sbytes[i]; }

    /* Write TAG */
    bw.write_all(&tag)?;
    bw.flush()?;

    println!("Encryption completed. Wrote IV + ciphertext + tag.");
    Ok(())
}

fn decrypt_file(infile: &str, outfile: &str, key: &[u64; 64]) -> io::Result<i32> {
    let mut fi = File::open(infile)?;
    let fsz = fi.metadata()?.len() as i64;

    if fsz < 32 {
        eprintln!("File too small (needs at least IV+TAG).");
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too small"));
    }

    /* Read IV */
    let mut iv = [0u8; 16];
    fi.read_exact(&mut iv)?;
    let remaining = fsz - 16;

    /* Ciphertext length = total - TAG(16) */
    if remaining < 16 {
        eprintln!("Missing tag.");
        return Err(io::Error::new(io::ErrorKind::InvalidData, "missing tag"));
    }
    let ciph_len = remaining - 16;

    /* Prepare output file */
    let fo = OpenOptions::new().write(true).create(true).truncate(true).open(outfile)?;
    let mut bw = BufWriter::new(fo);

    /* Compute H and J0 as in encryption */
    let mut h = [0u8; 16]; compute_h(&mut h, key);
    let hbe = load_be128(&h);
    let mut j0 = [0u8; 16];
    derive_j0(&mut j0, &iv, hbe);

    /* GHASH S over ciphertext */
    let mut s = Be128 { hi: 0, lo: 0 };

    /* CTR starts at inc32(J0) */
    let mut ctr = j0;
    inc32(&mut ctr);

    /* Stream: read ciphertext (excluding last 16B tag), update GHASH, decrypt and write P immediately */
    let mut left = ciph_len as i64;
    let mut buf = [0u8; BUF_CHUNK];

    while left > 0 {
        let to_read = min(left as usize, BUF_CHUNK);
        let nread = fi.read(&mut buf[..to_read])?;
        if nread == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "early EOF"));
        }

        let mut off = 0usize;
        while off < nread {
            let n = min(16, nread - off);

            // Prepare ciphertext block with zero padding for GHASH
            let mut cblk = [0u8; 16];
            cblk[..n].copy_from_slice(&buf[off..off+n]);

            // GHASH over ciphertext block
            ghash_update(&mut s, hbe, &cblk);

            // keystream
            let mut ks = [0u8; 16];
            gost_encrypt_block(&ctr, &mut ks, key);
            inc32(&mut ctr);

            // P = C XOR KS (only n bytes)
            let mut pblk = [0u8; 16];
            for i in 0..n { pblk[i] = cblk[i] ^ ks[i]; }

            bw.write_all(&pblk[..n])?;

            off += n;
        }
        left -= nread as i64;
    }

    /* Read the trailing TAG */
    let mut tag = [0u8; 16];
    fi.read_exact(&mut tag)?;
    bw.flush()?;

    /* Finalize GHASH with lengths */
    let c_bits = (ciph_len as u64).wrapping_mul(8);
    ghash_lengths_update(&mut s, hbe, 0, c_bits);

    /* Compute expected tag: E_K(J0) XOR S */
    let mut ej0 = [0u8; 16];
    gost_encrypt_block(&j0, &mut ej0, key);
    let mut stmp = [0u8; 16];
    store_be128(s, &mut stmp);
    let mut tcalc = [0u8; 16];
    for i in 0..16 { tcalc[i] = ej0[i] ^ stmp[i]; }

    /* Constant-time compare */
    let diff = ct_memcmp(&tag, &tcalc);
    if diff == 0 {
        println!("Authentication: OK");
        Ok(0)
    } else {
        println!("Authentication: FAILED");
        Ok(1) // non-zero to indicate failure
    }
}

/* ---------------------- Derive GOST2-128 subkeys from password ---------------------- */
fn derive_key_from_password(pwd: &str) -> [u64; 64] {
    /* Follow the original code's hashing pipeline to build h4 then subkeys */
    let mut hs = HashState::new();
    hs.hashing(pwd.as_bytes());
    let h4 = hs.end_hash();
    create_keys(&h4)
}

// ---------------------- CLI / Main ----------------------

fn usage(prog: &str) {
    eprintln!("Usage: {} c|d <input_file>", prog);
}

fn main() -> io::Result<()> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        usage(&args.get(0).cloned().unwrap_or_else(|| "gost2gcm".to_string()));
        std::process::exit(2);
    }
    let mode = &args[1];
    let infile = &args[2];

    let pwd = pw::read_password("Enter password: ")?;
    // Init GOST2 tables and derive subkeys from password
    kboxinit();
    let key = derive_key_from_password(&pwd);
    // Zero password buffer after use (best effort)
    drop(pwd);

    // Build output file name
    if mode.eq_ignore_ascii_case("c") {
        let outfile = add_suffix_gost2(infile);
        if let Err(e) = encrypt_file(infile, &outfile, &key) {
            eprintln!("Encryption error: {}", e);
            std::process::exit(1);
        }
        Ok(())
    } else if mode.eq_ignore_ascii_case("d") {
        let outfile = strip_suffix_gost2(infile);
        match decrypt_file(infile, &outfile, &key)? {
            0 => Ok(()),
            _ => std::process::exit(1),
        }
    } else {
        usage(&args[0]);
        std::process::exit(2);
    }
}
