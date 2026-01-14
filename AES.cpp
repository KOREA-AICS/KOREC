#include <iostream>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <cstring>
#include <array>

/**
 * @class AES_Optimized
 * @brief An AES implementation based on the FIPS-197 standard, optimized with T-Tables.
 *
 * This class supports AES-128, AES-192, and AES-256. The core encryption and
 * decryption routines are accelerated using pre-computed lookup tables (T-Tables),
 * which combine SubBytes, ShiftRows, and MixColumns into a single table lookup
 * operation per column.
 */
class AES_Optimized {
private:
    // --- FIPS-197 Standard Constant Tables ---
    static const uint8_t s_box[256];
    static const uint8_t inv_s_box[256];
    static const uint8_t Rcon[11];

    // --- T-Tables for Optimization ---
    // Encryption and decryption lookup tables merge multiple AES steps.
    uint32_t Te0[256], Te1[256], Te2[256], Te3[256]; // Encryption T-Tables
    uint32_t Td0[256], Td1[256], Td2[256], Td3[256]; // Decryption T-Tables

    // Round keys stored as 32-bit words.
    std::vector<uint32_t> round_keys;
    // Decryption round keys, pre-computed by applying InvMixColumns.
    // This is necessary because the T-Table optimization changes the operation order.
    std::vector<uint32_t> dec_round_keys;

    /**
     * @brief Performs multiplication in the Galois Field GF(2^8).
     * @param a The first operand.
     * @param b The second operand.
     * @return The product of a and b in GF(2^8).
     */
    uint8_t gmul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        for (int i = 0; i < 8; i++) {
            if (b & 1) {
                p ^= a;
            }
            bool hi_bit_set = (a & 0x80);
            a <<= 1;
            if (hi_bit_set) {
                a ^= 0x1B; // AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)
            }
            b >>= 1;
        }
        return p;
    }

    /**
     * @brief Pre-computes and initializes the T-Tables for encryption and decryption.
     * This method is called once during object construction to set up the lookup tables.
     */
    void build_tables() {
        for (int i = 0; i < 256; i++) {
            uint8_t s = s_box[i];
            uint8_t s2 = gmul(s, 2);
            uint8_t s3 = gmul(s, 3);

            // Te combines SubBytes and MixColumns for encryption
            uint32_t te_val = (static_cast<uint32_t>(s2) << 24) |
                              (static_cast<uint32_t>(s)  << 16) |
                              (static_cast<uint32_t>(s)  << 8)  |
                               static_cast<uint32_t>(s3);

            // Rotated versions for different columns (simulating ShiftRows)
            Te0[i] = te_val;
            Te1[i] = (te_val >> 8)  | (te_val << 24);
            Te2[i] = (te_val >> 16) | (te_val << 16);
            Te3[i] = (te_val >> 24) | (te_val << 8);

            uint8_t is = inv_s_box[i];
            uint8_t is9 = gmul(is, 9);
            uint8_t isB = gmul(is, 0xB);
            uint8_t isD = gmul(is, 0xD);
            uint8_t isE = gmul(is, 0xE);

            // Td combines InvSubBytes and InvMixColumns for decryption
            uint32_t td_val = (static_cast<uint32_t>(isE) << 24) |
                              (static_cast<uint32_t>(is9) << 16) |
                              (static_cast<uint32_t>(isD) << 8)  |
                               static_cast<uint32_t>(isB);

            // Rotated versions for different columns (simulating InvShiftRows)
            Td0[i] = td_val;
            Td1[i] = (td_val >> 8)  | (td_val << 24);
            Td2[i] = (td_val >> 16) | (td_val << 16);
            Td3[i] = (td_val >> 24) | (td_val << 8);
        }
    }

    // Converts 4 bytes into a 32-bit word (Big Endian).
    uint32_t bytes_to_uint32(const uint8_t* bytes) {
        return (static_cast<uint32_t>(bytes[0]) << 24) |
               (static_cast<uint32_t>(bytes[1]) << 16) |
               (static_cast<uint32_t>(bytes[2]) << 8)  |
                static_cast<uint32_t>(bytes[3]);
    }

    // Converts a 32-bit word into 4 bytes (Big Endian).
    void uint32_to_bytes(uint32_t word, uint8_t* bytes) {
        bytes[0] = (word >> 24) & 0xFF;
        bytes[1] = (word >> 16) & 0xFF;
        bytes[2] = (word >> 8)  & 0xFF;
        bytes[3] = word & 0xFF;
    }

    /**
     * @brief The Key Expansion routine from FIPS-197.
     * Generates the full set of round keys from the initial cipher key.
     * @param key The initial cipher key.
     * @param Nk The number of 32-bit words in the key (4, 6, or 8).
     * @param Nr The number of rounds (10, 12, or 14).
     */
    void key_expansion(const uint8_t* key, int Nk, int Nr) {
        round_keys.resize(4 * (Nr + 1));
        for (int i = 0; i < Nk; ++i) {
            round_keys[i] = bytes_to_uint32(key + i * 4);
        }

        for (int i = Nk; i < 4 * (Nr + 1); ++i) {
            uint32_t temp = round_keys[i - 1];
            if (i % Nk == 0) {
                // Apply RotWord, SubWord, and Rcon XOR for the key schedule.
                temp = (s_box[(temp >> 16) & 0xFF] << 24) |
                       (s_box[(temp >> 8)  & 0xFF] << 16) |
                       (s_box[temp & 0xFF] << 8)  |
                       (s_box[temp >> 24]);
                temp ^= (static_cast<uint32_t>(Rcon[i / Nk]) << 24);
            } else if (Nk > 6 && i % Nk == 4) {
                 // Additional SubWord step required for AES-256 key schedule.
                temp = (s_box[(temp >> 24) & 0xFF] << 24) |
                       (s_box[(temp >> 16) & 0xFF] << 16) |
                       (s_box[(temp >> 8)  & 0xFF] << 8)  |
                       (s_box[temp & 0xFF]);
            }
            round_keys[i] = round_keys[i - Nk] ^ temp;
        }
    }

    // Applies the InvMixColumns transformation to a single 32-bit word.
    uint32_t inv_mix_columns_word(uint32_t w) {
        uint8_t b[4];
        uint32_to_bytes(w, b);
        uint8_t res[4];
        res[0] = gmul(0x0e, b[0]) ^ gmul(0x0b, b[1]) ^ gmul(0x0d, b[2]) ^ gmul(0x09, b[3]);
        res[1] = gmul(0x09, b[0]) ^ gmul(0x0e, b[1]) ^ gmul(0x0b, b[2]) ^ gmul(0x0d, b[3]);
        res[2] = gmul(0x0d, b[0]) ^ gmul(0x09, b[1]) ^ gmul(0x0e, b[2]) ^ gmul(0x0b, b[3]);
        res[3] = gmul(0x0b, b[0]) ^ gmul(0x0d, b[1]) ^ gmul(0x09, b[2]) ^ gmul(0x0e, b[3]);
        return bytes_to_uint32(res);
    }


public:
    AES_Optimized(const uint8_t* key, int key_bits) {
        build_tables();
        int Nk = key_bits / 32;
        int Nr;
        switch(key_bits) {
            case 128: Nr = 10; break;
            case 192: Nr = 12; break;
            case 256: Nr = 14; break;
            default: throw std::invalid_argument("Invalid key size. Must be 128, 192, or 256 bits.");
        }
        key_expansion(key, Nk, Nr);

        // Pre-compute decryption keys. For T-Table based decryption, the intermediate
        // round keys must be transformed by InvMixColumns. The first and last round
        // keys remain unchanged as they are not used with MixColumns.
        dec_round_keys = round_keys;
        for (int round = 1; round < Nr; ++round) {
            for (int i = 0; i < 4; ++i) {
                dec_round_keys[round * 4 + i] = inv_mix_columns_word(round_keys[round * 4 + i]);
            }
        }
    }

    void encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext) {
        // Initial round: AddRoundKey
        uint32_t s0 = bytes_to_uint32(plaintext)      ^ round_keys[0];
        uint32_t s1 = bytes_to_uint32(plaintext + 4)  ^ round_keys[1];
        uint32_t s2 = bytes_to_uint32(plaintext + 8)  ^ round_keys[2];
        uint32_t s3 = bytes_to_uint32(plaintext + 12) ^ round_keys[3];

        int Nr = round_keys.size() / 4 - 1;

        // Main rounds: Use T-Tables to combine SubBytes, ShiftRows, MixColumns
        for (int round = 1; round < Nr; ++round) {
            uint32_t t0 = Te0[(s0 >> 24) & 0xFF] ^ Te1[(s1 >> 16) & 0xFF] ^ Te2[(s2 >> 8) & 0xFF] ^ Te3[s3 & 0xFF] ^ round_keys[round*4];
            uint32_t t1 = Te0[(s1 >> 24) & 0xFF] ^ Te1[(s2 >> 16) & 0xFF] ^ Te2[(s3 >> 8) & 0xFF] ^ Te3[s0 & 0xFF] ^ round_keys[round*4+1];
            uint32_t t2 = Te0[(s2 >> 24) & 0xFF] ^ Te1[(s3 >> 16) & 0xFF] ^ Te2[(s0 >> 8) & 0xFF] ^ Te3[s1 & 0xFF] ^ round_keys[round*4+2];
            uint32_t t3 = Te0[(s3 >> 24) & 0xFF] ^ Te1[(s0 >> 16) & 0xFF] ^ Te2[(s1 >> 8) & 0xFF] ^ Te3[s2 & 0xFF] ^ round_keys[round*4+3];
            s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        }

        // Final round: SubBytes, ShiftRows, AddRoundKey (no MixColumns)
        uint32_t t0 = (static_cast<uint32_t>(s_box[(s0 >> 24) & 0xFF]) << 24) |
                      (static_cast<uint32_t>(s_box[(s1 >> 16) & 0xFF]) << 16) |
                      (static_cast<uint32_t>(s_box[(s2 >> 8) & 0xFF]) << 8)   |
                       static_cast<uint32_t>(s_box[s3 & 0xFF]);
        uint32_t t1 = (static_cast<uint32_t>(s_box[(s1 >> 24) & 0xFF]) << 24) |
                      (static_cast<uint32_t>(s_box[(s2 >> 16) & 0xFF]) << 16) |
                      (static_cast<uint32_t>(s_box[(s3 >> 8) & 0xFF]) << 8)   |
                       static_cast<uint32_t>(s_box[s0 & 0xFF]);
        uint32_t t2 = (static_cast<uint32_t>(s_box[(s2 >> 24) & 0xFF]) << 24) |
                      (static_cast<uint32_t>(s_box[(s3 >> 16) & 0xFF]) << 16) |
                      (static_cast<uint32_t>(s_box[(s0 >> 8) & 0xFF]) << 8)   |
                       static_cast<uint32_t>(s_box[s1 & 0xFF]);
        uint32_t t3 = (static_cast<uint32_t>(s_box[(s3 >> 24) & 0xFF]) << 24) |
                      (static_cast<uint32_t>(s_box[(s0 >> 16) & 0xFF]) << 16) |
                      (static_cast<uint32_t>(s_box[(s1 >> 8) & 0xFF]) << 8)   |
                       static_cast<uint32_t>(s_box[s2 & 0xFF]);

        uint32_to_bytes(t0 ^ round_keys[Nr*4], ciphertext);
        uint32_to_bytes(t1 ^ round_keys[Nr*4+1], ciphertext + 4);
        uint32_to_bytes(t2 ^ round_keys[Nr*4+2], ciphertext + 8);
        uint32_to_bytes(t3 ^ round_keys[Nr*4+3], ciphertext + 12);
    }

    void decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext) {
        int Nr = round_keys.size() / 4 - 1;

        // Initial round: AddRoundKey (using the last encryption round key)
        uint32_t s0 = bytes_to_uint32(ciphertext)      ^ round_keys[Nr * 4];
        uint32_t s1 = bytes_to_uint32(ciphertext + 4)  ^ round_keys[Nr * 4 + 1];
        uint32_t s2 = bytes_to_uint32(ciphertext + 8)  ^ round_keys[Nr * 4 + 2];
        uint32_t s3 = bytes_to_uint32(ciphertext + 12) ^ round_keys[Nr * 4 + 3];

        // Main rounds: Use T-Tables and pre-computed decryption keys
        for (int round = Nr - 1; round >= 1; --round) {
            uint32_t t0 = Td0[(s0 >> 24) & 0xFF] ^ Td1[(s3 >> 16) & 0xFF] ^ Td2[(s2 >> 8) & 0xFF] ^ Td3[s1 & 0xFF] ^ dec_round_keys[round*4];
            uint32_t t1 = Td0[(s1 >> 24) & 0xFF] ^ Td1[(s0 >> 16) & 0xFF] ^ Td2[(s3 >> 8) & 0xFF] ^ Td3[s2 & 0xFF] ^ dec_round_keys[round*4+1];
            uint32_t t2 = Td0[(s2 >> 24) & 0xFF] ^ Td1[(s1 >> 16) & 0xFF] ^ Td2[(s0 >> 8) & 0xFF] ^ Td3[s3 & 0xFF] ^ dec_round_keys[round*4+2];
            uint32_t t3 = Td0[(s3 >> 24) & 0xFF] ^ Td1[(s2 >> 16) & 0xFF] ^ Td2[(s1 >> 8) & 0xFF] ^ Td3[s0 & 0xFF] ^ dec_round_keys[round*4+3];
            s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        }

        // Final round: InvSubBytes, InvShiftRows, AddRoundKey (no InvMixColumns)
        uint32_t t0 = (static_cast<uint32_t>(inv_s_box[(s0 >> 24) & 0xFF]) << 24) |
                      (static_cast<uint32_t>(inv_s_box[(s3 >> 16) & 0xFF]) << 16) |
                      (static_cast<uint32_t>(inv_s_box[(s2 >> 8) & 0xFF]) << 8)   |
                       static_cast<uint32_t>(inv_s_box[s1 & 0xFF]);
        uint32_t t1 = (static_cast<uint32_t>(inv_s_box[(s1 >> 24) & 0xFF]) << 24) |
                      (static_cast<uint32_t>(inv_s_box[(s0 >> 16) & 0xFF]) << 16) |
                      (static_cast<uint32_t>(inv_s_box[(s3 >> 8) & 0xFF]) << 8)   |
                       static_cast<uint32_t>(inv_s_box[s2 & 0xFF]);
        uint32_t t2 = (static_cast<uint32_t>(inv_s_box[(s2 >> 24) & 0xFF]) << 24) |
                      (static_cast<uint32_t>(inv_s_box[(s1 >> 16) & 0xFF]) << 16) |
                      (static_cast<uint32_t>(inv_s_box[(s0 >> 8) & 0xFF]) << 8)   |
                       static_cast<uint32_t>(inv_s_box[s3 & 0xFF]);
        uint32_t t3 = (static_cast<uint32_t>(inv_s_box[(s3 >> 24) & 0xFF]) << 24) |
                      (static_cast<uint32_t>(inv_s_box[(s2 >> 16) & 0xFF]) << 16) |
                      (static_cast<uint32_t>(inv_s_box[(s1 >> 8) & 0xFF]) << 8)   |
                       static_cast<uint32_t>(inv_s_box[s0 & 0xFF]);

        uint32_to_bytes(t0 ^ round_keys[0], plaintext);
        uint32_to_bytes(t1 ^ round_keys[1], plaintext + 4);
        uint32_to_bytes(t2 ^ round_keys[2], plaintext + 8);
        uint32_to_bytes(t3 ^ round_keys[3], plaintext + 12);
    }
};

// --- Constant Table Initialization (from FIPS-197) ---
const uint8_t AES_Optimized::s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t AES_Optimized::inv_s_box[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const uint8_t AES_Optimized::Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};


void print_hex_array(const std::string& label, const uint8_t* data, size_t len) {
    std::cout << label;
    std::cout << std::hex;
    for (size_t i = 0; i < len; ++i) {
        // Pad with a leading zero if necessary for uniform alignment
        if (data[i] < 16) std::cout << " 0"; else std::cout << " ";
        std::cout << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}

// NIST FIPS-197 Appendix B - AES-128 Test Vector
int main() {
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    uint8_t expected_ciphertext[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };

    uint8_t ciphertext[16];
    uint8_t decrypted_plaintext[16];

    try {
        AES_Optimized aes(key, 128);

        print_hex_array("Plaintext:           ", plaintext, 16);
        print_hex_array("Key:                 ", key, 16);
        std::cout << "---------------------------------------------------------" << std::endl;

        aes.encrypt_block(plaintext, ciphertext);
        print_hex_array("Encrypted Ciphertext:", ciphertext, 16);
        print_hex_array("Expected Ciphertext: ", expected_ciphertext, 16);
        std::cout << "---------------------------------------------------------" << std::endl;

        aes.decrypt_block(ciphertext, decrypted_plaintext);
        print_hex_array("Decrypted Plaintext: ", decrypted_plaintext, 16);
        print_hex_array("Original Plaintext:  ", plaintext, 16);

        bool ciphertext_match = (memcmp(ciphertext, expected_ciphertext, 16) == 0);
        bool plaintext_match = (memcmp(plaintext, decrypted_plaintext, 16) == 0);

        if (ciphertext_match && plaintext_match) {
            std::cout << "\nSuccess: NIST FIPS-197 test vector passed." << std::endl;
        } else {
            std::cout << "\nError: NIST FIPS-197 test vector failed." << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
