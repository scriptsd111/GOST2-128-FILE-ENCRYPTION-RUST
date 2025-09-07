/*
 * GOST2-128 Cipher
 * GOST2-128 by Alexander Pukall 2016
 * 
 * Based on the 25 Movember 1993 draft translation
 * by Aleksandr Malchik, with Whitfield Diffie, of the Government
 * Standard of the U.S.S.R. GOST 28149-89, "Cryptographic Transformation
 * Algorithm", effective 1 July 1990.  
 * 
 * 4096-bit keys with 64 * 64-bit subkeys
 * 
 * 128-bit block cipher (like AES) 64 rounds
 * 
 * Uses MD2II hash function to create the 64 subkeys
 * 
 * Code free for all, even for commercial software 
 * No restriction to use. Public Domain 
 * 
 * 
 */

// --- Rust port notes:
// - This is a direct translation of the original C code into Rust.
// - Global mutable state (x1, x2, h1, h2, k-tables) is kept as `static mut` and accessed within `unsafe` blocks,
//   to stay faithful to the original structure.
// - Arithmetic uses wrapping semantics where C would naturally wrap (e.g., u64 addition).
// - `create_keys` relies on the caller having a zero-initialized `key` array (as done in `main`),
//   matching the intended behavior of the C example outputs.

/*
  Cargo.toml
  * 
[package]
name = "gost2-128"
version = "0.1.0"
edition = "2024"

[dependencies]

*/

// cargo run --release

type Word64 = u64;

const N1: usize = 512; /* 4096-bit GOST2-128 key for 64 * 64-bit subkeys */

static mut X1: i32 = 0;
static mut X2: usize = 0;

static mut H2: [u8; N1] = [0; N1];
static mut H1: [u8; N1 * 3] = [0; N1 * 3];

/* initialize internal state */
fn init() {
    unsafe {
        X1 = 0;
        X2 = 0;
        for i in 0..N1 {
            H2[i] = 0;
        }
        for i in 0..N1 {
            H1[i] = 0;
        }
    }
}

fn hashing(t1: &[u8], mut b6: usize) {
    // static unsigned char s4[256] = { ... };
    // Keep as const; identical contents.
    const S4: [u8; 256] = [
        13,199, 11, 67,237,193,164, 77,115,184,141,222, 73, 38,147, 36,
       150, 87, 21,104, 12, 61,156,101,111,145,119, 22,207, 35,198, 37,
       171,167, 80, 30,219, 28,213,121, 86, 29,214,242,  6,  4, 89,162,
       110,175, 19,157,  3, 88,234, 94,144,118,159,239,100, 17,182,173,
       238, 68, 16, 79,132, 54,163, 52,  9, 58, 57, 55,229,192,170,226,
        56,231,187,158, 70,224,233,245, 26, 47, 32, 44,247,  8,251, 20,
       197,185,109,153,204,218, 93,178,212,137, 84,174, 24,120,130,149,
        72,180,181,208,255,189,152, 18,143,176, 60,249, 27,227,128,139,
       243,253, 59,123,172,108,211, 96,138, 10,215, 42,225, 40, 81, 65,
        90, 25, 98,126,154, 64,124,116,122,  5,  1,168, 83,190,131,191,
       244,240,235,177,155,228,125, 66, 43,201,248,220,129,188,230, 62,
        75, 71, 78, 34, 31,216,254,136, 91,114,106, 46,217,196, 92,151,
       209,133, 51,236, 33,252,127,179, 69,  7,183,105,146, 97, 39, 15,
       205,112,200,166,223, 45, 48,246,186, 41,148,140,107, 76, 85, 95,
       194,142, 50, 49,134, 23,135,169,221,210,203, 63,165, 82,161,202,
        53, 14,206,232,103,102,195,117,250, 99,  0, 74,160,241,  2,113
    ];

    let mut b4: usize = 0;
    unsafe {
        while b6 > 0 {
            while b6 > 0 && X2 < N1 {
                let b5 = t1[b4] as i32;
                b4 += 1;

                H1[X2 + N1] = b5 as u8;
                H1[X2 + (N1 * 2)] = (b5 as u8) ^ H1[X2];

                // x1 = h2[x2] ^= s4[b5 ^ x1];
                let idx = ((b5 ^ X1) & 0xFF) as usize;
                let val = H2[X2] ^ S4[idx];
                H2[X2] = val;
                X1 = val as i32;

                b6 -= 1;
                X2 += 1;
            }

            if X2 == N1 {
                let mut b2: i32 = 0;
                X2 = 0;

                for b3 in 0..(N1 + 2) {
                    for b1 in 0..(N1 * 3) {
                        // b2 = h1[b1] ^= s4[b2];
                        let idx = (b2 & 0xFF) as usize;
                        let newv = H1[b1] ^ S4[idx];
                        H1[b1] = newv;
                        b2 = newv as i32;
                    }
                    b2 = (b2 + b3 as i32) % 256;
                }
            }
        }
    }
}

fn end_fn(h4: &mut [u8; N1]) {
    unsafe {
        let n4 = N1 - X2;
        let mut h3 = [0u8; N1];
        for i in 0..n4 {
            h3[i] = n4 as u8;
        }
        hashing(&h3[..n4], n4);

        // hashing(h2, sizeof(h2));
        // We can pass a snapshot of H2; hashing only *reads* its argument and
        // updates global state H1/H2 internally, just like C code did.
        let snapshot_h2: Vec<u8> = H2[..].to_vec();
        hashing(&snapshot_h2, snapshot_h2.len());

        // for (i = 0; i < n1; i++) h4[i] = h1[i];
        for i in 0..N1 {
            h4[i] = H1[i];
        }
    }
}


/* create 64 * 64-bit subkeys from h4 hash */
fn create_keys(h4: &[u8; N1], key: &mut [Word64; 64]) {
    let mut k = 0usize;
    for i in 0..64 {
        // NOTE: identical construction as C: key[i] = (key[i]<<8) + (h4[k++] & 0xff)
        // In Rust we start from zeroed `key` in main to match intended behavior.
        for _z in 0..8 {
            key[i] = (key[i] << 8) + (h4[k] as Word64 & 0xff);
            k += 1;
        }
    }
}

static K1:  [u8; 16] = [0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3];
static K2:  [u8; 16] = [0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9];
static K3:  [u8; 16] = [0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB];
static K4:  [u8; 16] = [0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3];
static K5:  [u8; 16] = [0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2];
static K6:  [u8; 16] = [0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE];
static K7:  [u8; 16] = [0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC];
static K8:  [u8; 16] = [0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC];

static K9:  [u8; 16] = [0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1];
static K10: [u8; 16] = [0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF];
static K11: [u8; 16] = [0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0];
static K12: [u8; 16] = [0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB];
static K13: [u8; 16] = [0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC];
static K14: [u8; 16] = [0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0];
static K15: [u8; 16] = [0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7];
static K16: [u8; 16] = [0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2];

/* Byte-at-a-time substitution boxes */
static mut K175: [u8; 256] = [0; 256];
static mut K153: [u8; 256] = [0; 256];
static mut K131: [u8; 256] = [0; 256];
static mut K109: [u8; 256] = [0; 256];
static mut K87:  [u8; 256] = [0; 256];
static mut K65:  [u8; 256] = [0; 256];
static mut K43:  [u8; 256] = [0; 256];
static mut K21:  [u8; 256] = [0; 256];

/*
 * Build byte-at-a-time subtitution tables.
 * This must be called once for global setup.
 */
fn kboxinit() {
    unsafe {
        for i in 0u16..256 {
            let i8 = i as u8;
            K175[i as usize] = (K16[(i8 >> 4) as usize] << 4) | K15[(i8 & 15) as usize];
            K153[i as usize] = (K14[(i8 >> 4) as usize] << 4) | K13[(i8 & 15) as usize];
            K131[i as usize] = (K12[(i8 >> 4) as usize] << 4) | K11[(i8 & 15) as usize];
            K109[i as usize] = (K10[(i8 >> 4) as usize] << 4) | K9 [(i8 & 15) as usize];

            K87[i as usize]  = (K8 [(i8 >> 4) as usize] << 4) | K7 [(i8 & 15) as usize];
            K65[i as usize]  = (K6 [(i8 >> 4) as usize] << 4) | K5 [(i8 & 15) as usize];
            K43[i as usize]  = (K4 [(i8 >> 4) as usize] << 4) | K3 [(i8 & 15) as usize];
            K21[i as usize]  = (K2 [(i8 >> 4) as usize] << 4) | K1 [(i8 & 15) as usize];
        }
    }
}

/* #define TEST */

// The C version declares __inline__ f(). We'll keep it as a normal function.
// Argument/return are u64; rotate left by 11 bits matches ((x<<11)|(x>>(64-11))).
fn f(mut x: Word64) -> Word64 {
    let mut y = x >> 32;
    let mut z = x & 0xFFFF_FFFF;

    unsafe {
        // Faster path using prebuilt byte tables (like the non-TEST branch)
        y = ((K87[((y >> 24) & 0xFF) as usize] as Word64) << 24)
          | ((K65[((y >> 16) & 0xFF) as usize] as Word64) << 16)
          | ((K43[((y >> 8)  & 0xFF) as usize] as Word64) << 8)
          |  (K21[( y        & 0xFF) as usize] as Word64);

        z = ((K175[((z >> 24) & 0xFF) as usize] as Word64) << 24)
          | ((K153[((z >> 16) & 0xFF) as usize] as Word64) << 16)
          | ((K131[((z >> 8)  & 0xFF) as usize] as Word64) << 8)
          |  (K109[( z        & 0xFF) as usize] as Word64);

        x = (y << 32) | (z & 0xFFFF_FFFF);
    }

    // Rotate left 11 bits
    x.rotate_left(11)
}

fn gostcrypt(input: [Word64; 2], key: &[Word64; 64]) -> [Word64; 2] {
    let mut ngost1 = input[0];
    let mut ngost2 = input[1];

    let mut k = 0usize;
    for _ in 0..32 {
        // ngost2 ^= f(ngost1+key[k++]);
        ngost2 ^= f(ngost1.wrapping_add(key[k]));
        k += 1;
        // ngost1 ^= f(ngost2+key[k++]);
        ngost1 ^= f(ngost2.wrapping_add(key[k]));
        k += 1;
    }

    [ngost2, ngost1]
}

fn gostdecrypt(input: [Word64; 2], key: &[Word64; 64]) -> [Word64; 2] {
    let mut ngost1 = input[0];
    let mut ngost2 = input[1];

    let mut k: isize = 63;
    for _ in 0..32 {
        // ngost2 ^= f(ngost1+key[k--]);
        ngost2 ^= f(ngost1.wrapping_add(key[k as usize]));
        k -= 1;
        // ngost1 ^= f(ngost2+key[k--]);
        ngost1 ^= f(ngost2.wrapping_add(key[k as usize]));
        k -= 1;
    }

    [ngost2, ngost1]
}

fn main() {
    // unsigned char text[33]; /* up to 256 chars for the password */
    //                             /* password can be hexadecimal */
    // In Rust we use &str literals; we pass exactly 32 bytes to hashing, like C.
    let mut key: [Word64; 64] = [0; 64];
    let mut plain: [Word64; 2];
    let mut cipher: [Word64; 2];
    let mut decrypted: [Word64; 2];

    let mut h4 = [0u8; N1];

    kboxinit();

    println!("GOST2-128 by Alexander PUKALL 2016 \n 128-bit block 4096-bit subkeys 64 rounds");
    println!("Code can be freely use even for commercial software");
    println!("Based on GOST 28147-89 by Aleksandr Malchik with Whitfield Diffie\n");

    /* The key creation procedure is slow, it only needs to be done once */
    /* as long as the user does not change the key. You can encrypt and decrypt */
    /* as many blocks as you want without having to hash the key again. */
    /* kboxinit(); -> only once */
    /* init(); hashing(text,length);  end(h4); -> only once */
    /* create_keys(h4,key); -> only once too */

    /* EXAMPLE 1 */

    init();

    let text1 = "My secret password!0123456789abc";
    // hashing(text, 32);
    hashing(&text1.as_bytes()[..32], 32);
    // end(h4); /* h4 = 4096-bit key from hash "My secret password!0123456789abc */
    end_fn(&mut h4);
    // create_keys(h4,key); /* create 64 * 64-bit subkeys from h4 hash */
    create_keys(&h4, &mut key);

    // plain[0] = 0xFEFEFEFEFEFEFEFE; /* 0xFE... GOST2-128 block plaintext */
    // plain[1] = 0xFEFEFEFEFEFEFEFE;
    plain = [0xFEFEFEFEFEFEFEFE, 0xFEFEFEFEFEFEFEFE];

    println!("Key 1:{}", text1);
    println!("Plaintext  1: {:016X}{:016X}", plain[0], plain[1]);

    cipher = gostcrypt(plain, &key);

    println!("Encryption 1: {:016X}{:016X}", cipher[0], cipher[1]);

    decrypted = gostdecrypt(cipher, &key);

    println!("Decryption 1: {:016X}{:016X}\n", decrypted[0], decrypted[1]);

    /* EXAMPLE 2 */

    init();

    let text2 = "My secret password!0123456789ABC";

    hashing(&text2.as_bytes()[..32], 32);
    end_fn(&mut h4); /* h4 = 4096-bit key from hash "My secret password!0123456789ABC */
    create_keys(&h4, &mut key); /* create 64 * 64-bit subkeys from h4 hash */

    // 0x000... block
    plain = [0x0000000000000000, 0x0000000000000000];

    println!("Key 2:{}", text2);
    println!("Plaintext  2: {:016X}{:016X}", plain[0], plain[1]);

    cipher = gostcrypt(plain, &key);

    println!("Encryption 2: {:016X}{:016X}", cipher[0], cipher[1]);

    decrypted = gostdecrypt(cipher, &key);

    println!("Decryption 2: {:016X}{:016X}\n", decrypted[0], decrypted[1]);

    /* EXAMPLE 3 */

    init();

    let text3 = "My secret password!0123456789abZ";

    hashing(&text3.as_bytes()[..32], 32);
    end_fn(&mut h4); /* h4 = 4096-bit key from hash "My secret password!0123456789abZ */
    create_keys(&h4, &mut key); /* create 64 * 64-bit subkeys from h4 hash */

    // 0x...0001 block
    plain = [0x0000000000000000, 0x0000000000000001];

    println!("Key 3:{}", text3);
    println!("Plaintext  3: {:016X}{:016X}", plain[0], plain[1]);

    cipher = gostcrypt(plain, &key);

    println!("Encryption 3: {:016X}{:016X}", cipher[0], cipher[1]);

    decrypted = gostdecrypt(cipher, &key);

    println!("Decryption 3: {:016X}{:016X}\n", decrypted[0], decrypted[1]);
}

/*
 
Key 1:My secret password!0123456789abc
Plaintext  1: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE
Encryption 1: 8CA4C196B773D9C9A00AD3931F9B2B09
Decryption 1: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE

Key 2:My secret password!0123456789ABC
Plaintext  2: 00000000000000000000000000000000
Encryption 2: 96AB544910861D5B22B04FC984D80098
Decryption 2: 00000000000000000000000000000000

Key 3:My secret password!0123456789abZ
Plaintext  3: 00000000000000000000000000000001
Encryption 3: ACF914AC22AE2079390BC240ED51916F
Decryption 3: 00000000000000000000000000000001

*/
