#include <iostream>
#include <vector>
#include <cstdint>
#include <array>
#include <stdexcept>

// FIPS 46-3 표준을 준수하며 성능을 최적화한 DES 클래스
class DES_NIST {
private:
    // --- 상수 테이블 (FIPS 46-3 표준) ---
    static const uint8_t IP[64];
    static const uint8_t FP[64];
    static const uint8_t E[48];
    static const uint8_t P[32];
    static const uint8_t PC1[56];
    static const uint8_t PC2[48];
    static const uint8_t SHIFTS[16];
    static const uint8_t S_BOXES[8][4][16];

    // 16개의 48비트 라운드 키 (uint64_t로 저장)
    std::array<uint64_t, 16> round_keys;

    // --- 비트 단위 헬퍼 함수 (최적화) ---

    // 바이트 배열을 uint64_t로 변환 (Big Endian)
    uint64_t bytes_to_uint64(const uint8_t* bytes) {
        uint64_t block = 0;
        for (int i = 0; i < 8; ++i) {
            block = (block << 8) | bytes[i];
        }
        return block;
    }

    // uint64_t를 바이트 배열로 변환 (Big Endian)
    void uint64_to_bytes(uint64_t block, uint8_t* bytes) {
        for (int i = 7; i >= 0; --i) {
            bytes[i] = block & 0xFF;
            block >>= 8;
        }
    }

    // 주어진 테이블에 따라 비트 순서를 재배치하는 함수 (일반화된 순열)
    template<size_t N_IN, size_t N_OUT>
    uint64_t permute(uint64_t input, const uint8_t table[N_OUT]) {
        uint64_t output = 0;
        for (size_t i = 0; i < N_OUT; ++i) {
            // FIPS 테이블은 1-based index를 사용하므로 (N_IN - table[i])로 비트 위치 계산
            uint64_t bit = (input >> (N_IN - table[i])) & 1;
            output |= (bit << (N_OUT - 1 - i));
        }
        return output;
    }

    // 28비트 값에 대한 왼쪽 순환 시프트 연산
    uint32_t left_circular_shift_28bit(uint32_t val, int num_shifts) {
        // 연산이 28비트 공간 내에서만 이루어지도록 보장
        return ((val << num_shifts) | (val >> (28 - num_shifts))) & 0x0FFFFFFF;
    }

    // --- DES 핵심 함수 ---

    // DES의 라운드 함수 (F 함수)
    uint32_t feistel_function(uint32_t right_half, uint64_t key) {
        // 1. 확장 (Expansion): 32비트 -> 48비트
        uint64_t expanded_right = permute<32, 48>(right_half, E);

        // 2. 키 혼합 (Key Mixing)
        uint64_t xored = expanded_right ^ key;

        // 3. S-Box 치환 (Substitution): 48비트 -> 32비트
        uint32_t s_box_output = 0;
        for (int i = 0; i < 8; ++i) {
            uint8_t six_bits = (xored >> (42 - i * 6)) & 0x3F; // 6비트 추출
            uint8_t row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
            uint8_t col = (six_bits & 0x1E) >> 1;
            uint8_t val = S_BOXES[i][row][col];
            s_box_output |= (static_cast<uint32_t>(val) << (28 - i * 4));
        }

        // 4. 순열 (Permutation)
        return permute<32, 32>(s_box_output, P);
    }
    
    // 64비트 마스터 키로부터 16개의 48비트 라운드 키를 생성
    void generate_keys(const uint8_t* key_bytes) {
        uint64_t master_key = bytes_to_uint64(key_bytes);
        
        // PC1 (64비트 -> 56비트)
        uint64_t permuted_key_56 = permute<64, 56>(master_key, PC1);

        uint32_t C = (permuted_key_56 >> 28) & 0x0FFFFFFF;
        uint32_t D = permuted_key_56 & 0x0FFFFFFF;

        for (int i = 0; i < 16; ++i) {
            C = left_circular_shift_28bit(C, SHIFTS[i]);
            D = left_circular_shift_28bit(D, SHIFTS[i]);

            uint64_t combined_key = (static_cast<uint64_t>(C) << 28) | D;
            
            // PC2 (56비트 -> 48비트)
            round_keys[i] = permute<56, 48>(combined_key, PC2);
        }
    }


public:
    // 생성자: 키를 받아 라운드 키를 미리 생성
    DES_NIST(const uint8_t key[8]) {
        generate_keys(key);
    }

    // 64비트 블록 암호화
    void encrypt_block(const uint8_t plaintext[8], uint8_t ciphertext[8]) {
        uint64_t block = bytes_to_uint64(plaintext);

        // 1. 초기 순열
        block = permute<64, 64>(block, IP);
        
        uint32_t L = block >> 32;
        uint32_t R = block & 0xFFFFFFFF;

        // 2. 16 라운드
        for (int i = 0; i < 16; ++i) {
            uint32_t temp_R = R;
            R = L ^ feistel_function(R, round_keys[i]);
            L = temp_R;
        }

        // 32비트 스왑
        block = (static_cast<uint64_t>(R) << 32) | L;

        // 3. 최종 순열
        block = permute<64, 64>(block, FP);

        uint64_to_bytes(block, ciphertext);
    }

    // 64비트 블록 복호화
    void decrypt_block(const uint8_t ciphertext[8], uint8_t plaintext[8]) {
        uint64_t block = bytes_to_uint64(ciphertext);

        // 1. 초기 순열
        block = permute<64, 64>(block, IP);
        
        uint32_t L = block >> 32;
        uint32_t R = block & 0xFFFFFFFF;

        // 2. 16 라운드 (키를 역순으로 사용)
        for (int i = 15; i >= 0; --i) {
            uint32_t temp_R = R;
            R = L ^ feistel_function(R, round_keys[i]);
            L = temp_R;
        }

        // 32비트 스왑
        block = (static_cast<uint64_t>(R) << 32) | L;

        // 3. 최종 순열
        block = permute<64, 64>(block, FP);

        uint64_to_bytes(block, plaintext);
    }
};

// --- DES 상수 테이블 초기화 ---
// (FIPS 46-3 표준 명세서에 따름)

const uint8_t DES_NIST::IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};
const uint8_t DES_NIST::FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
};
const uint8_t DES_NIST::E[48] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};
const uint8_t DES_NIST::P[32] = {
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
};
const uint8_t DES_NIST::PC1[56] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
};
const uint8_t DES_NIST::PC2[48] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};
const uint8_t DES_NIST::SHIFTS[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
const uint8_t DES_NIST::S_BOXES[8][4][16] = {
    {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
     {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
     {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
     {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
    {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
     {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
     {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
     {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
    {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
     {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
     {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
     {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
    {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
     {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
     {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
     {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
    {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
     {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
     {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
     {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
    {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
     {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
     {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
     {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
    {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
     {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
     {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
     {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
    {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
     {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
     {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
     {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}
};

// 16진수 문자열 출력을 위한 헬퍼 함수
void print_hex(const std::string& label, const uint8_t* data, size_t len) {
    std::cout << label;
    std::cout << std::hex;
    for (size_t i = 0; i < len; ++i) {
        std::cout << (data[i] < 16 ? "0" : "") << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    // NIST FIPS 46-3 Appendix의 테스트 벡터
    uint8_t key[8]        = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    uint8_t plaintext[8]  = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    uint8_t expected_ciphertext[8] = { 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05 };
    
    uint8_t ciphertext[8];
    uint8_t decrypted_plaintext[8];

    try {
        DES_NIST des(key);

        print_hex("Plaintext:           ", plaintext, 8);
        print_hex("Key:                 ", key, 8);

        // 암호화
        des.encrypt_block(plaintext, ciphertext);
        print_hex("Encrypted Ciphertext:", ciphertext, 8);
        print_hex("Expected Ciphertext: ", expected_ciphertext, 8);

        // 복호화
        des.decrypt_block(ciphertext, decrypted_plaintext);
        print_hex("Decrypted Plaintext: ", decrypted_plaintext, 8);

        // 결과 검증
        bool match = true;
        for(int i=0; i<8; ++i) {
            if(plaintext[i] != decrypted_plaintext[i] || ciphertext[i] != expected_ciphertext[i]) {
                match = false;
                break;
            }
        }
        
        if (match) {
            std::cout << "\nSuccess: NIST test vector passed." << std::endl;
        } else {
            std::cout << "\nError: NIST test vector failed." << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
    }

    return 0;
}

