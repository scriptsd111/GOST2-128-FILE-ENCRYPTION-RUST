
/* - we implement the same utility in pure Rust.
 * - Password input uses the `rpassword` crate (no libc/termios).
 * - Random IV uses the `getrandom` crate (cross-platform OS RNG).
 */

// cargo run --release

/*
 *  Cargo.toml

[package]
name = "gost2file"
version = "0.1.0"
edition = "2021"

[dependencies]
rpassword = "7.3"
getrandom = "0.2"

*/
use std::cmp::min;
use std::env;
use std::fs::{File, OpenOptions, remove_file};
use std::io::{self, Read, Write, BufReader, BufWriter, Seek, SeekFrom};
use std::time::{SystemTime, UNIX_EPOCH};

type Word64 = u64;
const N1: usize = 512; // original C: 4096-bit GOST2-128 key for 64 * 64-bit subkeys

const BLOCK_SIZE: usize = 16;
const READ_CHUNK: usize = 64 * 1024;

/* =========================
 *      GOST2-128 CORE
 * ========================= */

// original C: struct with internal state for MD2II hashing
struct KeyHash {
    x1: i32,
    x2: usize,
    h2: [u8; N1],
    h1: [u8; N1 * 3],
}

impl KeyHash {
    // original C: static void init_gost_keyhash(void)
    fn init_gost_keyhash(&mut self) {
        self.x1 = 0;
        self.x2 = 0;
        self.h2.fill(0);
        self.h1.fill(0);
    }

    // original C: static void hashing(unsigned char t1[], size_t b6)
    fn hashing(&mut self, t1: &[u8]) {
        // original C: static unsigned char s4[256] = {...};
        const S4: [u8; 256] = [
            13,199,11,67,237,193,164,77,115,184,141,222,73,38,147,36,150,87,21,104,12,61,156,101,111,145,
            119,22,207,35,198,37,171,167,80,30,219,28,213,121,86,29,214,242,6,4,89,162,110,175,19,157,3,88,234,94,144,118,159,239,100,17,182,173,238,
            68,16,79,132,54,163,52,9,58,57,55,229,192,170,226,56,231,187,158,70,224,233,245,26,47,32,44,247,8,251,20,197,185,109,153,204,218,93,178,
            212,137,84,174,24,120,130,149,72,180,181,208,255,189,152,18,143,176,60,249,27,227,128,139,243,253,59,123,172,108,211,96,138,10,215,42,225,40,81,
            65,90,25,98,126,154,64,124,116,122,5,1,168,83,190,131,191,244,240,235,177,155,228,125,66,43,201,248,220,129,188,230,62,75,71,78,34,31,216,
            254,136,91,114,106,46,217,196,92,151,209,133,51,236,33,252,127,179,69,7,183,105,146,97,39,15,205,112,200,166,223,45,48,246,186,41,148,140,107,
            76,85,95,194,142,50,49,134,23,135,169,221,210,203,63,165,82,161,202,53,14,206,232,103,102,195,117,250,99,0,74,160,241,2,113
        ];
        let mut b4 = 0usize;
        let mut b6 = t1.len();
        while b6 > 0 {
            while b6 > 0 && self.x2 < N1 {
                let b5 = t1[b4] as usize;
                b4 += 1;
                self.h1[self.x2 + N1] = b5 as u8;
                self.h1[self.x2 + (N1 * 2)] = (b5 as u8) ^ self.h1[self.x2];
                self.x1 = self.h2[self.x2] as i32 ^ (S4[(b5 ^ (self.x1 as usize)) & 255] as i32);
                self.h2[self.x2] = self.x1 as u8;
                b6 -= 1;
                self.x2 += 1;
            }
            if self.x2 == N1 {
                let mut b2 = 0usize;
                self.x2 = 0;
                for b3 in 0..(N1 + 2) {
                    for b1 in 0..(N1 * 3) {
                        // fix: keep types aligned (usize ^ usize) then cast back to u8
                        b2 = (self.h1[b1] as usize) ^ (S4[b2] as usize);
                        self.h1[b1] = b2 as u8;
                    }
                    b2 = (b2 + b3) % 256;
                }
            }
        }
    }

    // original C: static void end_gost_keyhash(unsigned char h4[])
    fn end_gost_keyhash(&mut self, h4: &mut [u8; N1]) {
        let mut h3 = [0u8; N1];
        let n4 = N1 - self.x2;
        for j in 0..n4 { h3[j] = n4 as u8; }
        self.hashing(&h3[..n4]);
        let h2_copy = self.h2; // Rust fix: avoid simultaneous mutable+immutable borrow
        self.hashing(&h2_copy);
        for j in 0..N1 { h4[j] = self.h1[j]; }
    }
}

// original C: create 64 * 64-bit subkeys from h4 hash
fn create_keys(h4: &[u8; N1], key: &mut [Word64; 64]) {
    let mut k = 0usize;
    for i in 0..64 {
        let mut v: u64 = 0;
        for _ in 0..8 {
            v = (v << 8) + (h4[k] as u64);
            k += 1;
        }
        key[i] = v;
    }
}

// original C: GOST K-boxes
const K1:  [u8; 16] = [0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3];
const K2:  [u8; 16] = [0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9];
const K3:  [u8; 16] = [0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB];
const K4:  [u8; 16] = [0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3];
const K5:  [u8; 16] = [0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2];
const K6:  [u8; 16] = [0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE];
const K7:  [u8; 16] = [0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC];
const K8:  [u8; 16] = [0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC];

const K9:  [u8; 16] = [0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1];
const K10: [u8; 16] = [0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF];
const K11: [u8; 16] = [0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0];
const K12: [u8; 16] = [0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB];
const K13: [u8; 16] = [0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC];
const K14: [u8; 16] = [0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0];
const K15: [u8; 16] = [0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7];
const K16: [u8; 16] = [0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2];

// original C: precompute combined k-box tables
struct KBoxes {
    k175: [u8; 256], k153: [u8; 256], k131: [u8; 256], k109: [u8; 256],
    k87:  [u8; 256], k65:  [u8; 256], k43:  [u8; 256], k21:  [u8; 256],
}
impl KBoxes {
    fn new() -> Self {
        let mut kb = KBoxes {
            k175: [0;256], k153:[0;256], k131:[0;256], k109:[0;256],
            k87:[0;256], k65:[0;256], k43:[0;256], k21:[0;256],
        };
        kb.kboxinit();
        kb
    }

    // original C: static void kboxinit(void)
    fn kboxinit(&mut self) {
        for i in 0..256 {
            self.k175[i] = (K16[(i >> 4) & 15] << 4) | K15[i & 15];
            self.k153[i] = (K14[(i >> 4) & 15] << 4) | K13[i & 15];
            self.k131[i] = (K12[(i >> 4) & 15] << 4) | K11[i & 15];
            self.k109[i] = (K10[(i >> 4) & 15] << 4) | K9[i & 15];
            self.k87[i]  = (K8[(i >> 4) & 15]  << 4) | K7[i & 15];
            self.k65[i]  = (K6[(i >> 4) & 15]  << 4) | K5[i & 15];
            self.k43[i]  = (K4[(i >> 4) & 15]  << 4) | K3[i & 15];
            self.k21[i]  = (K2[(i >> 4) & 15]  << 4) | K1[i & 15];
        }
    }

    // original C: inline word64 f(word64 x)
    fn f(&self, x: Word64) -> Word64 {
        let mut y = (x >> 32) as u32;
        let mut z = (x & 0xffff_ffff) as u32;

        let y0 = self.k87[((y >> 24) & 255) as usize] as u32;
        let y1 = self.k65[((y >> 16) & 255) as usize] as u32;
        let y2 = self.k43[((y >>  8) & 255) as usize] as u32;
        let y3 = self.k21[(y & 255) as usize] as u32;
        y = (y0 << 24) | (y1 << 16) | (y2 << 8) | y3;

        let z0 = self.k175[((z >> 24) & 255) as usize] as u32;
        let z1 = self.k153[((z >> 16) & 255) as usize] as u32;
        let z2 = self.k131[((z >>  8) & 255) as usize] as u32;
        let z3 = self.k109[(z & 255) as usize] as u32;
        z = (z0 << 24) | (z1 << 16) | (z2 << 8) | z3;

        let out = (((y as u64) << 32) | (z as u64 & 0xffff_ffff)).rotate_left(11);
        out
    }

    // original C: static void gostcrypt(word64 input[2], word64 key[64])
    fn gostcrypt(&self, input: [Word64;2], key: &[Word64;64]) -> [Word64;2] {
        let (mut a, mut b) = (input[0], input[1]);
        let mut k = 0usize;
        for _ in 0..32 {
            b ^= self.f(a.wrapping_add(key[k])); k+=1;
            a ^= self.f(b.wrapping_add(key[k])); k+=1;
        }
        [b,a]
    }

    // original C: static void gostdecrypt(word64 input[2], word64 key[64])
    fn gostdecrypt(&self, input: [Word64;2], key: &[Word64;64]) -> [Word64;2] {
        let (mut a, mut b) = (input[0], input[1]);
        let mut k: isize = 63;
        for _ in 0..32 {
            b ^= self.f(a.wrapping_add(key[k as usize])); k-=1;
            a ^= self.f(b.wrapping_add(key[k as usize])); k-=1;
        }
        [b,a]
    }
}

/* =========================
 *          SHA-256
 * ========================= */

#[derive(Clone)]
struct Sha256Ctx {
    state: [u32; 8],
    bitlen: u64,
    data: [u8; 64],
    datalen: usize,
}

// original C: #define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#[inline] fn rotright(a: u32, b: u32) -> u32 { (a >> b) | (a << (32 - b)) }
// original C: #define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#[inline] fn ch(x:u32,y:u32,z:u32)->u32{ (x & y) ^ (!x & z) }
// original C: #define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#[inline] fn maj(x:u32,y:u32,z:u32)->u32{ (x & y) ^ (x & z) ^ (y & z) }
// original C: #define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#[inline] fn ep0(x:u32)->u32{ rotright(x,2) ^ rotright(x,13) ^ rotright(x,22) }
// original C: #define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#[inline] fn ep1(x:u32)->u32{ rotright(x,6) ^ rotright(x,11) ^ rotright(x,25) }
// original C: #define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#[inline] fn sig0(x:u32)->u32{ rotright(x,7) ^ rotright(x,18) ^ (x >> 3) }
// original C: #define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
#[inline] fn sig1(x:u32)->u32{ rotright(x,17) ^ rotright(x,19) ^ (x >> 10) }

const K256: [u32;64] = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];

// original C: static void sha256_transform(ctx, data)
fn sha256_transform(ctx: &mut Sha256Ctx, data: &[u8;64]) {
    let mut m = [0u32;64];
    for i in 0..16 {
        let j = i*4;
        m[i] = ((data[j] as u32) << 24) |
               ((data[j+1] as u32) << 16) |
               ((data[j+2] as u32) << 8) |
               (data[j+3] as u32);
    }
    for i in 16..64 {
        m[i] = sig1(m[i-2]).wrapping_add(m[i-7]).wrapping_add(sig0(m[i-15])).wrapping_add(m[i-16]);
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
        (ctx.state[0],ctx.state[1],ctx.state[2],ctx.state[3],ctx.state[4],ctx.state[5],ctx.state[6],ctx.state[7]);

    for i in 0..64 {
        let t1 = h.wrapping_add(ep1(e)).wrapping_add(ch(e,f,g)).wrapping_add(K256[i]).wrapping_add(m[i]);
        let t2 = ep0(a).wrapping_add(maj(a,b,c));
        h=g; g=f; f=e; e=d.wrapping_add(t1); d=c; c=b; b=a; a=t1.wrapping_add(t2);
    }

    ctx.state[0] = ctx.state[0].wrapping_add(a);
    ctx.state[1] = ctx.state[1].wrapping_add(b);
    ctx.state[2] = ctx.state[2].wrapping_add(c);
    ctx.state[3] = ctx.state[3].wrapping_add(d);
    ctx.state[4] = ctx.state[4].wrapping_add(e);
    ctx.state[5] = ctx.state[5].wrapping_add(f);
    ctx.state[6] = ctx.state[6].wrapping_add(g);
    ctx.state[7] = ctx.state[7].wrapping_add(h);
}

// original C: static void sha256_init(ctx)
fn sha256_init(ctx: &mut Sha256Ctx) {
    ctx.datalen = 0;
    ctx.bitlen = 0;
    ctx.state = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
}

// original C: static void sha256_update(ctx, data, len)
fn sha256_update(ctx: &mut Sha256Ctx, data: &[u8]) {
    for &b in data {
        ctx.data[ctx.datalen] = b;
        ctx.datalen += 1;
        if ctx.datalen == 64 {
            let block = ctx.data;
            sha256_transform(ctx, &block);
            ctx.bitlen = ctx.bitlen.wrapping_add(512);
            ctx.datalen = 0;
        }
    }
}

// original C: static void sha256_final(ctx, hash)
fn sha256_final(ctx: &mut Sha256Ctx, hash: &mut [u8;32]) {
    let mut i = ctx.datalen;
    ctx.bitlen = ctx.bitlen.wrapping_add((ctx.datalen as u64) * 8);

    // Pad
    ctx.data[i] = 0x80; i+=1;
    if i > 56 {
        while i < 64 { ctx.data[i]=0; i+=1; }
        let block = ctx.data;
        sha256_transform(ctx, &block);
        i = 0;
    }
    while i < 56 { ctx.data[i]=0; i+=1; }

    // Append length (big-endian)
    let bitlen = ctx.bitlen;
    for j in (0..8).rev() {
        ctx.data[i] = ((bitlen >> (j*8)) & 0xFF) as u8; i+=1;
    }
    let block = ctx.data;
    sha256_transform(ctx, &block);

    for i in 0..8 {
        hash[i*4+0] = ((ctx.state[i] >> 24) & 0xFF) as u8;
        hash[i*4+1] = ((ctx.state[i] >> 16) & 0xFF) as u8;
        hash[i*4+2] = ((ctx.state[i] >> 8) & 0xFF) as u8;
        hash[i*4+3] = (ctx.state[i] & 0xFF) as u8;
    }
}

/* =========================
 *       Utilities
 * ========================= */

fn be_bytes_to_words(input: &[u8;16]) -> [Word64;2] {
    let mut a: u64 = 0;
    let mut b: u64 = 0;
    for i in 0..8 { a = (a<<8) | input[i] as u64; }
    for i in 8..16 { b = (b<<8) | input[i] as u64; }
    [a,b]
}
fn be_words_to_bytes(input: &[Word64;2], out: &mut [u8;16]) {
    for i in (0..8).rev() { out[7 - i]  = ((input[0] >> (i*8)) & 0xFF) as u8; }
    for i in (0..8).rev() { out[15 - i] = ((input[1] >> (i*8)) & 0xFF) as u8; }
}

// original C: password prompt not echoed
fn prompt_password(buf: &mut String, prompt: &str) -> io::Result<()> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let pw = rpassword::read_password()?;
    *buf = pw;
    Ok(())
}

// original C: generate_iv using OS RNG (fallback is weak; LAST RESORT)
fn generate_iv(iv: &mut [u8; BLOCK_SIZE]) {
    if getrandom::getrandom(iv).is_ok() { return; }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
    let mut x = now ^ 0x9E3779B97F4A7C15u64;
    for i in 0..BLOCK_SIZE {
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        iv[i] = (x.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8;
    }
}

// original C: derive from password via GOST2-128 MD2II hashing -> 64 subkeys
fn derive_gost_subkeys_from_password(password: &str, subkeys: &mut [Word64;64]) {
    let mut h4 = [0u8; N1];
    let mut hk = KeyHash { x1:0, x2:0, h2:[0;N1], h1:[0;N1*3] };
    hk.init_gost_keyhash();
    hk.hashing(password.as_bytes());
    hk.end_gost_keyhash(&mut h4);
    create_keys(&h4, subkeys);
}

// original C: PKCS#7 padding helpers
fn pkcs7_pad(buf: &mut Vec<u8>) {
    let pad = BLOCK_SIZE - (buf.len() % BLOCK_SIZE);
    for _ in 0..pad { buf.push(pad as u8); }
}
fn pkcs7_unpad(buf: &mut Vec<u8>) -> bool {
    if buf.is_empty() || (buf.len() % BLOCK_SIZE) != 0 { return false; }
    let pad = *buf.last().unwrap() as usize;
    if pad == 0 || pad > BLOCK_SIZE { return false; }
    let n = buf.len();
    for i in 0..pad {
        if buf[n - 1 - i] as usize != pad { return false; }
    }
    buf.truncate(n - pad);
    true
}

/* =========================
 *   CBC Encrypt / Decrypt
 * ========================= */

// original C: static void cbc_encrypt_stream(...)
fn cbc_encrypt_stream<R: Read, W: Write>(
    mut fin: R,
    mut fout: W,
    kb: &KBoxes,
    subkeys: &[Word64;64],
    iv: &[u8;BLOCK_SIZE],
    out_hash: &mut [u8;32]
) -> io::Result<()> {
    // Write IV in clear (as in C)
    fout.write_all(iv)?;

    let mut prev = *iv;

    // Hash over ciphertext only (not IV)
    let mut hctx = Sha256Ctx { state:[0;8], bitlen:0, data:[0;64], datalen:0 };
    sha256_init(&mut hctx);

    // Streaming: carry buffer
    let mut carry = Vec::<u8>::new();
    let mut inbuf = vec![0u8; READ_CHUNK];

    loop {
        let r = fin.read(&mut inbuf)?;
        if r == 0 { break; }
        carry.extend_from_slice(&inbuf[..r]);

        while carry.len() >= BLOCK_SIZE {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&carry[..BLOCK_SIZE]);
            carry.drain(0..BLOCK_SIZE);

            // CBC XOR
            for i in 0..BLOCK_SIZE { block[i] ^= prev[i]; }

            // Encrypt one block
            let inw = be_bytes_to_words(&block);
            let outw = kb.gostcrypt(inw, subkeys);
            let mut ob = [0u8;16];
            be_words_to_bytes(&outw, &mut ob);

            // Write + hash
            fout.write_all(&ob)?;
            sha256_update(&mut hctx, &ob);

            // Update CBC state
            prev = ob;
        }
    }

    // Final: pad remaining (even if zero -> adds one full block of padding)
    pkcs7_pad(&mut carry);
    let mut off = 0usize;
    while off < carry.len() {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(&carry[off..off+BLOCK_SIZE]);
        for i in 0..BLOCK_SIZE { block[i] ^= prev[i]; }
        let inw = be_bytes_to_words(&block);
        let outw = kb.gostcrypt(inw, subkeys);
        let mut ob = [0u8;16];
        be_words_to_bytes(&outw, &mut ob);
        fout.write_all(&ob)?;
        sha256_update(&mut hctx, &ob);
        prev = ob;
        off += BLOCK_SIZE;
    }

    // Append SHA-256
    sha256_final(&mut hctx, out_hash);
    fout.write_all(out_hash)?;
    Ok(())
}

// original C: static int cbc_decrypt_stream(...) -> returns auth_ok
fn cbc_decrypt_stream<R: Read + Seek, W: Write>(
    mut fin: R,
    mut fout: W,
    kb: &KBoxes,
    subkeys: &[Word64;64]
) -> io::Result<bool> {
    // Layout: [IV (16)] [ciphertext ...] [hash (32)]
    let fsz = fin.seek(SeekFrom::End(0))?;
    if fsz < (BLOCK_SIZE as u64 + 32) {
        eprintln!("Error: input too small.");
        return Err(io::Error::new(io::ErrorKind::InvalidData, "too small"));
    }
    let payload_end = fsz - 32;

    // Read IV
    fin.seek(SeekFrom::Start(0))?;
    let mut iv = [0u8; BLOCK_SIZE];
    fin.read_exact(&mut iv)?;

    // Read stored hash
    fin.seek(SeekFrom::Start(payload_end))?;
    let mut stored_hash = [0u8; 32];
    fin.read_exact(&mut stored_hash)?;

    // Prepare to read ciphertext (between IV and payload_end)
    fin.seek(SeekFrom::Start(BLOCK_SIZE as u64))?;
    let mut remaining = (payload_end - BLOCK_SIZE as u64) as usize;
    if remaining == 0 || (remaining % BLOCK_SIZE) != 0 {
        eprintln!("Error: invalid ciphertext size.");
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad size"));
    }

    let mut prev = iv;
    let mut hctx = Sha256Ctx { state:[0;8], bitlen:0, data:[0;64], datalen:0 };
    sha256_init(&mut hctx);

    let mut inbuf = vec![0u8; READ_CHUNK];
    let mut pending_plain: Option<[u8;16]> = None;

    while remaining > 0 {
        let mut toread = min(remaining, READ_CHUNK);
        // ensure multiple of block size
        toread -= toread % BLOCK_SIZE;
        fin.read_exact(&mut inbuf[..toread])?;
        remaining -= toread;

        // Hash over ciphertext chunk
        sha256_update(&mut hctx, &inbuf[..toread]);

        // Process blocks
        let mut off = 0usize;
        while off < toread {
            let mut cblock = [0u8; BLOCK_SIZE];
            cblock.copy_from_slice(&inbuf[off..off+BLOCK_SIZE]);

            // Decrypt
            let inw = be_bytes_to_words(&cblock);
            let outw = kb.gostdecrypt(inw, subkeys);
            let mut pblock = [0u8; BLOCK_SIZE];
            be_words_to_bytes(&outw, &mut pblock);
            // CBC XOR
            for i in 0..BLOCK_SIZE { pblock[i] ^= prev[i]; }

            // Write previous plaintext (keep final for padding removal)
            if let Some(prev_plain) = pending_plain.take() {
                fout.write_all(&prev_plain)?;
            }
            pending_plain = Some(pblock);

            // Update CBC chain
            prev = cblock;
            off += BLOCK_SIZE;
        }
    }

    // After loop, pending_plain must hold the final padded block
    let mut last = match pending_plain.take() {
        Some(b) => b.to_vec(),
        None => return Err(io::Error::new(io::ErrorKind::InvalidData, "no final block")),
    };

    if !pkcs7_unpad(&mut last) {
        eprintln!("Error: invalid padding.");
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad padding"));
    }
    if !last.is_empty() {
        fout.write_all(&last)?;
    }

    // Verify hash
    let mut calc_hash = [0u8;32];
    sha256_final(&mut hctx, &mut calc_hash);
    Ok(calc_hash == stored_hash)
}

/* =========================
 *            MAIN
 * ========================= */

// original C: static void usage(prog)
fn usage(prog: &str) {
    eprintln!("Usage: {} c|d <input_file>", prog);
}

fn make_output_name_encrypt(input: &str) -> String {
    format!("{}.gost2", input)
}
fn make_output_name_decrypt(input: &str) -> String {
    if input.ends_with(".gost2") {
        input[..input.len()-6].to_string()
    } else {
        format!("{}.dec", input)
    }
}

// original C: int main(int argc, char** argv)
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        usage(&args.get(0).map(String::as_str).unwrap_or("gost2file"));
        std::process::exit(1);
    }
    let mode_encrypt = args[1] == "c";
    let mode_decrypt = args[1] == "d";
    if !mode_encrypt && !mode_decrypt {
        usage(&args[0]);
        std::process::exit(1);
    }

    let inpath = &args[2];
    let outpath = if mode_encrypt {
        make_output_name_encrypt(inpath)
    } else {
        make_output_name_decrypt(inpath)
    };

    // Open I/O
    let fin = match File::open(inpath) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error: cannot open input '{}': {}", inpath, e);
            std::process::exit(1);
        }
    };
    let fout = match OpenOptions::new().create(true).write(true).truncate(true).open(&outpath) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error: cannot create output '{}': {}", outpath, e);
            std::process::exit(1);
        }
    };
    let mut fin = BufReader::new(fin);
    let mut fout = BufWriter::new(fout);

    // Read password (not echoed)
    let mut password = String::new();
    if let Err(e) = prompt_password(&mut password, "Enter password: ") {
        eprintln!("Error reading password: {}", e);
        let _ = remove_file(&outpath);
        std::process::exit(1);
    }

    // kboxinit();
    let kb = KBoxes::new();
    let mut subkeys = [0u64;64];

    // derive_gost_subkeys_from_password(password, subkeys);
    derive_gost_subkeys_from_password(&password, &mut subkeys);

    // Zero password buffer in memory (best-effort)
    unsafe {
        let v = password.as_mut_vec();
        for b in v.iter_mut() { *b = 0; }
    }

    let mut err = false;
    if mode_encrypt {
        let mut iv = [0u8; BLOCK_SIZE];
        let mut hash_out = [0u8; 32];
        // generate_iv(iv);
        generate_iv(&mut iv);
        // cbc_encrypt_stream(fin, fout, subkeys, iv, &err, hash_out);
        if let Err(e) = cbc_encrypt_stream(&mut fin, &mut fout, &kb, &subkeys, &iv, &mut hash_out) {
            eprintln!("Operation failed due to an error: {}", e);
            err = true;
        } else {
            println!("Encryption completed. Output: {}", outpath);
        }
    } else {
        // Need a Seek for decrypt to locate hash at end
        let mut fin_file = match File::open(inpath) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Error: cannot re-open input '{}': {}", inpath, e);
                let _ = remove_file(&outpath);
                std::process::exit(1);
            }
        };
        // int auth_ok = cbc_decrypt_stream(fin, fout, subkeys);
        match cbc_decrypt_stream(&mut fin_file, &mut fout, &kb, &subkeys) {
            Ok(auth_ok) => {
                println!("Decryption completed. Output: {}", outpath);
                println!("Authentication {}", if auth_ok { "OK" } else { "FAILED" });
                if !auth_ok {
                    eprintln!("Warning: output written but authentication FAILED.");
                }
            }
            Err(e) => {
                eprintln!("Operation failed due to an error: {}", e);
                err = true;
            }
        }
    }

    if let Err(e) = fout.flush() {
        eprintln!("Error flushing output: {}", e);
        err = true;
    }

    if err {
        // Best-effort: remove incomplete output
        let _ = remove_file(&outpath);
        std::process::exit(2);
    }
}
