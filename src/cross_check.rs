//! Cross-check tests to verify Rust implementation matches Zig implementation.
//!
//! These tests use fixed inputs and produce deterministic outputs that can be
//! compared against the Zig implementation.

#[cfg(test)]
mod tests {
    use crate::common::lfsr_next_128;
    use crate::hctr2fp::{decode_base_radix, encode_base_radix, first_block_length};
    use crate::*;

    /// Helper to format bytes as hex string for output.
    fn hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn cross_check_hctr2_128_basic() {
        let key = [0x01u8; 16];
        let cipher = Hctr2_128::new(&key);

        let plaintext = b"Hello, this is a test message that is longer than one block!";
        let tweak = b"test tweak data";

        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();

        println!("HCTR2-128 Basic Test:");
        println!("  Key:        {}", hex(&key));
        println!("  Tweak:      {}", hex(tweak));
        println!("  Plaintext:  {}", hex(plaintext));
        println!("  Ciphertext: {}", hex(&ciphertext));

        let mut decrypted = vec![0u8; plaintext.len()];
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn cross_check_hctr2_256_basic() {
        let key = [0x02u8; 32];
        let cipher = Hctr2_256::new(&key);

        let plaintext = b"This is another test message for HCTR2-256 with a longer key size!";
        let tweak = b"another test tweak";

        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();

        println!("HCTR2-256 Basic Test:");
        println!("  Key:        {}", hex(&key));
        println!("  Tweak:      {}", hex(tweak));
        println!("  Plaintext:  {}", hex(plaintext));
        println!("  Ciphertext: {}", hex(&ciphertext));

        let mut decrypted = vec![0u8; plaintext.len()];
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn cross_check_hctr3_128_basic() {
        let key = [0x01u8; 16];
        let cipher = Hctr3_128::new(&key);

        let plaintext = b"Hello, this is a test message that is longer than one block!";
        let tweak = b"test tweak data";

        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();

        println!("HCTR3-128 Basic Test:");
        println!("  Key:        {}", hex(&key));
        println!("  Tweak:      {}", hex(tweak));
        println!("  Plaintext:  {}", hex(plaintext));
        println!("  Ciphertext: {}", hex(&ciphertext));

        let mut decrypted = vec![0u8; plaintext.len()];
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn cross_check_hctr3_256_basic() {
        let key = [0x02u8; 32];
        let cipher = Hctr3_256::new(&key);

        let plaintext = b"This is another test message for HCTR3-256 with a longer key size!";
        let tweak = b"another test tweak";

        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();

        println!("HCTR3-256 Basic Test:");
        println!("  Key:        {}", hex(&key));
        println!("  Tweak:      {}", hex(tweak));
        println!("  Plaintext:  {}", hex(plaintext));
        println!("  Ciphertext: {}", hex(&ciphertext));

        let mut decrypted = vec![0u8; plaintext.len()];
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn cross_check_lfsr_128() {
        let initial = [0x01u8; 16];
        let mut state = initial;

        println!("LFSR-128 Evolution Test:");
        println!("  Initial: {}", hex(&state));

        for i in 1..=10 {
            state = lfsr_next_128(&state);
            println!("  State {:2}: {}", i, hex(&state));
        }

        let mut state2 = [0xFFu8; 16];
        println!("\nLFSR-128 with MSB set:");
        println!("  Initial: {}", hex(&state2));
        for i in 1..=5 {
            state2 = lfsr_next_128(&state2);
            println!("  State {:2}: {}", i, hex(&state2));
        }
    }

    #[test]
    fn cross_check_chctr2_128_basic() {
        let key = [0x42u8; 32];
        let cipher = Chctr2_128::new(&key);

        let plaintext = b"CHCTR2 test message with some length!";
        let tweak = b"chctr2 tweak";

        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();

        println!("CHCTR2-128 Basic Test:");
        println!("  Key:        {}", hex(&key));
        println!("  Tweak:      {}", hex(tweak));
        println!("  Plaintext:  {}", hex(plaintext));
        println!("  Ciphertext: {}", hex(&ciphertext));

        let mut decrypted = vec![0u8; plaintext.len()];
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn cross_check_hctr2_twkd_128_basic() {
        let master_key = [0x55u8; 16];
        let cipher = Hctr2TwKD_128::new(&master_key);

        let plaintext = b"HCTR2-TwKD test message!";
        let tweak = b"twkd tweak";

        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();

        println!("HCTR2-TwKD-128 Basic Test:");
        println!("  Master Key: {}", hex(&master_key));
        println!("  Tweak:      {}", hex(tweak));
        println!("  Plaintext:  {}", hex(plaintext));
        println!("  Ciphertext: {}", hex(&ciphertext));

        let mut decrypted = vec![0u8; plaintext.len()];
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn cross_check_encode_decode_radix_10() {
        let value: u128 = 0x0123456789ABCDEF_FEDCBA9876543210;
        let mut digits = vec![0u8; first_block_length(10)];
        encode_base_radix(value, 10, &mut digits);

        println!("Base-10 Encode/Decode Test:");
        println!("  Value:  {:032x}", value);
        println!("  Digits: {:?}", digits);

        let decoded = decode_base_radix(&digits, 10).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn cross_check_encode_decode_radix_16() {
        let value: u128 = 0xDEADBEEFCAFEBABE_0123456789ABCDEF;
        let mut digits = vec![0u8; first_block_length(16)];
        encode_base_radix(value, 16, &mut digits);

        println!("Base-16 Encode/Decode Test:");
        println!("  Value:  {:032x}", value);
        println!("  Digits: {:?}", digits);

        let decoded = decode_base_radix(&digits, 16).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn cross_check_hctr2fp_decimal() {
        let key = [0x42u8; 16];
        let cipher = Hctr2Fp_128_Decimal::new(&key);

        let value: u128 = 0x0123456789ABCDEF_FEDCBA9876543210;
        let first_len = first_block_length(10);
        let mut plaintext = vec![0u8; first_len + 10]; // first block + 10 tail digits
        encode_base_radix(value, 10, &mut plaintext[..first_len]);
        for i in first_len..plaintext.len() {
            plaintext[i] = ((i - first_len) % 10) as u8;
        }

        let tweak = b"test_tweak";
        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.encrypt(&plaintext, tweak, &mut ciphertext).unwrap();

        println!("HCTR2-FP-128-Decimal Test:");
        println!("  Key:        {}", hex(&key));
        println!("  Tweak:      {}", hex(tweak));
        println!("  Plaintext:  {:?}", plaintext);
        println!("  Ciphertext: {:?}", ciphertext);

        let mut decrypted = vec![0u8; plaintext.len()];
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn cross_check_hctr2fp_hex() {
        let key = [0x99u8; 16];
        let cipher = Hctr2Fp_128_Hex::new(&key);

        let value: u128 = 0xDEADBEEFCAFEBABE_123456789ABCDEF0;
        let first_len = first_block_length(16);
        let mut plaintext = vec![0u8; first_len + 8];
        encode_base_radix(value, 16, &mut plaintext[..first_len]);
        for i in first_len..plaintext.len() {
            plaintext[i] = ((i - first_len) % 16) as u8;
        }

        let tweak = b"hex_tweak";
        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.encrypt(&plaintext, tweak, &mut ciphertext).unwrap();

        println!("HCTR2-FP-128-Hex Test:");
        println!("  Key:        {}", hex(&key));
        println!("  Tweak:      {}", hex(tweak));
        println!("  Plaintext:  {:?}", plaintext);
        println!("  Ciphertext: {:?}", ciphertext);

        let mut decrypted = vec![0u8; plaintext.len()];
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn cross_check_hctr3fp_decimal() {
        let key = [0x42u8; 16];
        let cipher = Hctr3Fp_128_Decimal::new(&key);

        let value: u128 = 0x0123456789ABCDEF_FEDCBA9876543210;
        let first_len = first_block_length(10);
        let mut plaintext = vec![0u8; first_len + 10];
        encode_base_radix(value, 10, &mut plaintext[..first_len]);
        for i in first_len..plaintext.len() {
            plaintext[i] = ((i - first_len) % 10) as u8;
        }

        let tweak = b"test_tweak";
        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.encrypt(&plaintext, tweak, &mut ciphertext).unwrap();

        println!("HCTR3-FP-128-Decimal Test:");
        println!("  Key:        {}", hex(&key));
        println!("  Tweak:      {}", hex(tweak));
        println!("  Plaintext:  {:?}", plaintext);
        println!("  Ciphertext: {:?}", ciphertext);

        let mut decrypted = vec![0u8; plaintext.len()];
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn cross_check_hctr3fp_hex() {
        let key = [0x99u8; 16];
        let cipher = hctr3fp::Hctr3Fp_128_Hex::new(&key);

        let value: u128 = 0xDEADBEEFCAFEBABE_123456789ABCDEF0;
        let first_len = first_block_length(16);
        let mut plaintext = vec![0u8; first_len + 8];
        encode_base_radix(value, 16, &mut plaintext[..first_len]);
        for i in first_len..plaintext.len() {
            plaintext[i] = ((i - first_len) % 16) as u8;
        }

        let tweak = b"hex_tweak";
        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.encrypt(&plaintext, tweak, &mut ciphertext).unwrap();

        println!("HCTR3-FP-128-Hex Test:");
        println!("  Key:        {}", hex(&key));
        println!("  Tweak:      {}", hex(tweak));
        println!("  Plaintext:  {:?}", plaintext);
        println!("  Ciphertext: {:?}", ciphertext);

        let mut decrypted = vec![0u8; plaintext.len()];
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn cross_check_chctr2_256_basic() {
        let key = [0x42u8; 64];
        let cipher = Chctr2_256::new(&key);

        let plaintext = b"CHCTR2-256 test message with some length!";
        let tweak = b"chctr2-256 tweak";

        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();

        println!("CHCTR2-256 Basic Test:");
        println!("  Key:        {}", hex(&key));
        println!("  Tweak:      {}", hex(tweak));
        println!("  Plaintext:  {}", hex(plaintext));
        println!("  Ciphertext: {}", hex(&ciphertext));

        let mut decrypted = vec![0u8; plaintext.len()];
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn cross_check_hctr2_twkd_256_basic() {
        let master_key = [0x55u8; 32];
        let cipher = Hctr2TwKD_256::new(&master_key);

        let plaintext = b"HCTR2-TwKD-256 test message!";
        let tweak = b"twkd256 tweak";

        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.encrypt(plaintext, tweak, &mut ciphertext).unwrap();

        println!("HCTR2-TwKD-256 Basic Test:");
        println!("  Master Key: {}", hex(&master_key));
        println!("  Tweak:      {}", hex(tweak));
        println!("  Plaintext:  {}", hex(plaintext));
        println!("  Ciphertext: {}", hex(&ciphertext));

        let mut decrypted = vec![0u8; plaintext.len()];
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn cross_check_hctr2fp_256_decimal() {
        let key = [0x42u8; 32];
        let cipher = Hctr2Fp_256_Decimal::new(&key);

        let value: u128 = 0x0123456789ABCDEF_FEDCBA9876543210;
        let first_len = first_block_length(10);
        let mut plaintext = vec![0u8; first_len + 10];
        encode_base_radix(value, 10, &mut plaintext[..first_len]);
        for i in first_len..plaintext.len() {
            plaintext[i] = ((i - first_len) % 10) as u8;
        }

        let tweak = b"test256_tweak";
        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.encrypt(&plaintext, tweak, &mut ciphertext).unwrap();

        println!("HCTR2-FP-256-Decimal Test:");
        println!("  Key:        {}", hex(&key));
        println!("  Tweak:      {}", hex(tweak));
        println!("  Plaintext:  {:?}", plaintext);
        println!("  Ciphertext: {:?}", ciphertext);

        let mut decrypted = vec![0u8; plaintext.len()];
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn cross_check_hctr3fp_256_decimal() {
        let key = [0x42u8; 32];
        let cipher = Hctr3Fp_256_Decimal::new(&key);

        let value: u128 = 0x0123456789ABCDEF_FEDCBA9876543210;
        let first_len = first_block_length(10);
        let mut plaintext = vec![0u8; first_len + 10];
        encode_base_radix(value, 10, &mut plaintext[..first_len]);
        for i in first_len..plaintext.len() {
            plaintext[i] = ((i - first_len) % 10) as u8;
        }

        let tweak = b"test256_tweak";
        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher.encrypt(&plaintext, tweak, &mut ciphertext).unwrap();

        println!("HCTR3-FP-256-Decimal Test:");
        println!("  Key:        {}", hex(&key));
        println!("  Tweak:      {}", hex(tweak));
        println!("  Plaintext:  {:?}", plaintext);
        println!("  Ciphertext: {:?}", ciphertext);

        let mut decrypted = vec![0u8; plaintext.len()];
        cipher.decrypt(&ciphertext, tweak, &mut decrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn cross_check_deterministic_vectors() {
        println!("\n=== DETERMINISTIC TEST VECTORS ===\n");

        {
            let key = [0u8; 16];
            let cipher = Hctr2_128::new(&key);
            let plaintext = [0x00u8; 16];
            let tweak = b"";
            let mut ciphertext = [0u8; 16];
            cipher.encrypt(&plaintext, tweak, &mut ciphertext).unwrap();
            println!("Test 1: HCTR2-128 zero key, 16-byte zero plaintext, empty tweak");
            println!("  Ciphertext: {}", hex(&ciphertext));
        }

        {
            let key = [0u8; 16];
            let cipher = Hctr3_128::new(&key);
            let plaintext = [0x00u8; 16];
            let tweak = b"";
            let mut ciphertext = [0u8; 16];
            cipher.encrypt(&plaintext, tweak, &mut ciphertext).unwrap();
            println!("Test 2: HCTR3-128 zero key, 16-byte zero plaintext, empty tweak");
            println!("  Ciphertext: {}", hex(&ciphertext));
        }

        {
            let key = [0u8; 16];
            let cipher = Hctr2Fp_128_Decimal::new(&key);
            let mut plaintext = [0u8; 39];
            plaintext[0] = 1;
            plaintext[1] = 2;
            plaintext[2] = 3;
            let tweak = b"";
            let mut ciphertext = [0u8; 39];
            cipher.encrypt(&plaintext, tweak, &mut ciphertext).unwrap();
            println!("Test 3: HCTR2-FP-128 decimal, zero key, digits [1,2,3,0...], empty tweak");
            println!("  Ciphertext: {:?}", ciphertext);
        }

        {
            let key = [0u8; 16];
            let cipher = Hctr3Fp_128_Decimal::new(&key);
            let mut plaintext = [0u8; 39];
            plaintext[0] = 1;
            plaintext[1] = 2;
            plaintext[2] = 3;
            let tweak = b"";
            let mut ciphertext = [0u8; 39];
            cipher.encrypt(&plaintext, tweak, &mut ciphertext).unwrap();
            println!("Test 4: HCTR3-FP-128 decimal, zero key, digits [1,2,3,0...], empty tweak");
            println!("  Ciphertext: {:?}", ciphertext);
        }

        {
            let state0 = [0x01u8; 16];
            let state1 = lfsr_next_128(&state0);
            let state2 = lfsr_next_128(&state1);
            println!("Test 5: LFSR-128 evolution from [0x01; 16]");
            println!("  State 0: {}", hex(&state0));
            println!("  State 1: {}", hex(&state1));
            println!("  State 2: {}", hex(&state2));
        }
    }
}
