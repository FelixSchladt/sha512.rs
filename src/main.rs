use std::env;
use std::fs;

// This has been written as an exercise, for the original specification please refer to:
// https://datatracker.ietf.org/doc/html/rfc4634 

//ouput array of u8 as one u64
fn as_u64_be(array: &[u8]) -> u64 {
    ((array[0] as u64) << 56)
        + ((array[1] as u64) << 48)
        + ((array[2] as u64) << 40)
        + ((array[3] as u64) << 32)
        + ((array[4] as u64) << 24)
        + ((array[5] as u64) << 16)
        + ((array[6] as u64) << 8)
        + ((array[7] as u64) << 0)
}

//** These are predefeined logical definitions from the spec
//rotate x right for the given amount n
fn rotr(x: u64, n: u32) -> u64 {
    return x.rotate_right(n);
}

//shift x right for the given amount n
fn shr(x: u64, n: u64) -> u64 {
    return x >> n;
}

// XOR modulus with negation mod
fn ch(x: u64, y: u64, z: u64) -> u64 {
    return (x & y) ^ ((!x) & z);
}

// xor mod
fn maj(x: u64, y: u64, z: u64) -> u64 {
    return (x & y) ^ (x & z) ^ (y & z);
}

// logical shifting and xor combination
fn bsig0(x: u64) -> u64 {
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}

// logical shifting and xor combination
fn bsig1(x: u64) -> u64 {
    return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}

// logical shifting and xor combination
fn ssig0(x: u64) -> u64 {
    return rotr(x, 1) ^ rotr(x, 8) ^ shr(x, 7);
}

// logical shifting and xor combination
fn ssig1(x: u64) -> u64 {
    return rotr(x, 19) ^ rotr(x, 61) ^ shr(x, 6);
}
//**

fn sha512(inital_msg: &str, initial_len: usize) {

    //predefined values by the specification    
    let k:[u64; 80] = [0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc, 
         0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
         0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
         0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
         0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
         0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
         0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
         0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
         0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
         0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
         0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
         0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
         0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
         0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
         0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
         0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
         0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
         0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
         0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
         0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817];

    let mut H:[u64; 8] = [0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179];

    //read msg into vec
    let mut msg: Vec<u8> = Vec::new();
    for character in inital_msg.bytes() {
        msg.push(character);
    }

    //Add padding
    msg.push(128);
    let mut lc = msg.len();
    while ((lc + 8) % 128) != 0 {
        //add fill upd with zeros until 512bit block is complete
        msg.push(0);
        lc += 1;
    }

    let bitlen = initial_len * 8;
    let msg_len_le = bitlen.to_be_bytes();
    //add length to the end of the last block
    for byte in msg_len_le {
        msg.push(byte);
    }

    //parse each array of [8; u8] as u64
    let mut msg_parsed: Vec<u64> = Vec::new();
    let len = msg.len();
    let mut offset = 0;
    while offset < len-1 {
        msg_parsed.push(as_u64_be(&msg[offset..(offset+8)]));
        offset += 8;
    } // -> results in vector with u64 blocks
 
    let mut offset = 0;
    let len = msg_parsed.len();
    while offset < len-1 {

        //prepare the message schedule w:
        let mut w:[u64;80] = [0;80];

        //parse 16 u64 from the message
        for i in 0..16 {
            w[i] = msg_parsed[offset+i];
        }
        //parse 64 logically shifted combinations of the previous 16 word blocks
        for i in 16..80 {
            w[i] = ssig1(w[i-2]).wrapping_add(w[i-7].wrapping_add(ssig0(w[i-15]).wrapping_add(w[i-16]))); 
        }


        //Initialize the working variables:
        let mut a = H[0];
        let mut b = H[1];
        let mut c = H[2];
        let mut d = H[3];
        let mut e = H[4];
        let mut f = H[5];
        let mut g = H[6];
        let mut h = H[7];

        //Perform the main hash computation -> 80 rounds
        for i in 0..80 {
            //main shifting of variables -> wrapping is enabled
            let t1 = h.wrapping_add(bsig1(e).wrapping_add(ch(e, f, g).wrapping_add(k[i].wrapping_add(w[i]))));
            let t2 = bsig0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d .wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        //add the results of this round to our pre_value hash array (with wrapping)
        H[0] = a.wrapping_add(H[0]);
        H[1] = b.wrapping_add(H[1]);
        H[2] = c.wrapping_add(H[2]);
        H[3] = d.wrapping_add(H[3]);
        H[4] = e.wrapping_add(H[4]);
        H[5] = f.wrapping_add(H[5]);
        H[6] = g.wrapping_add(H[6]);
        H[7] = h.wrapping_add(H[7]);

        offset += 16;
    }

    //print the resulting hash as hexadecimals -> 016 is required so rust does not cut off zeros in the front
    println!("{:016x}{:016x}{:016x}{:016x}{:016x}{:016x}{:016x}{:016x}", H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]);
}

fn main() {
    //collect args
    let mut args: Vec<String> = env::args().collect();
    let len = args.len();
    args.push(String::from(""));

    //read second parameter as string
    if &args[1] == "-s" && len == 3 {
        sha512(&args[2], args[2].len());
    }
    //check for help message
    else if &args[1] == "-h" || &args[1] == "--help" {
        println!("Usage: {} [OPTION]... [FILE]...\nPrint or check sha512 (512-bit) checksums.\n    -h, --help      show this menu\n    -s              take string parameter as hash source
", args[0])
    }
    //read text from file
    else if len == 2 {
        let contents = fs::read_to_string(&args[1]).expect("Error reading the given file");
        sha512(&contents[..], contents.len());
    }
    //show message if invalid options are entered
    else {
        println!(
            "Error: invalid options set.\nTry '{} --help' for more information.",
            args[0]
        );
    }
}
