#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

// AES参数
#define Nb 4
#define Nk 4  // AES-128
#define Nr 10

// S盒
static const uint8_t sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// 逆S盒
static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// 轮常数
static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// 密钥扩展
void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key) {
    unsigned i, j, k;
    uint8_t temp[4];
    
    // 第一个密钥就是原始密钥
    for (i = 0; i < Nk; i++) {
        RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    // 扩展其余密钥
    for (i = Nk; i < Nb * (Nr + 1); i++) {
        k = (i - 1) * 4;
        temp[0] = RoundKey[k + 0];
        temp[1] = RoundKey[k + 1];
        temp[2] = RoundKey[k + 2];
        temp[3] = RoundKey[k + 3];

        if (i % Nk == 0) {
            // 旋转字
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // S盒替换
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];

            // 异或轮常数
            temp[0] ^= Rcon[i/Nk];
        }

        j = i * 4;
        k = (i - Nk) * 4;
        RoundKey[j + 0] = RoundKey[k + 0] ^ temp[0];
        RoundKey[j + 1] = RoundKey[k + 1] ^ temp[1];
        RoundKey[j + 2] = RoundKey[k + 2] ^ temp[2];
        RoundKey[j + 3] = RoundKey[k + 3] ^ temp[3];
    }
}

// 字节替换
void SubBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

// 逆字节替换
void InvSubBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

// 行移位
void ShiftRows(uint8_t* state) {
    uint8_t temp;

    // 第2行循环左移1字节
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // 第3行循环左移2字节
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // 第4行循环左移3字节
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

// 逆行移位
void InvShiftRows(uint8_t* state) {
    uint8_t temp;

    // 第2行循环右移1字节
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // 第3行循环右移2字节
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // 第4行循环右移3字节
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

// 有限域乘法
uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t hi_bit_set;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    return p;
}

// 列混淆
void MixColumns(uint8_t* state) {
    uint8_t tmp[4];
    for (int i = 0; i < 4; i++) {
        tmp[0] = state[i*4];
        tmp[1] = state[i*4+1];
        tmp[2] = state[i*4+2];
        tmp[3] = state[i*4+3];
        
        state[i*4]   = gmul(tmp[0], 2) ^ gmul(tmp[1], 3) ^ gmul(tmp[2], 1) ^ gmul(tmp[3], 1);
        state[i*4+1] = gmul(tmp[0], 1) ^ gmul(tmp[1], 2) ^ gmul(tmp[2], 3) ^ gmul(tmp[3], 1);
        state[i*4+2] = gmul(tmp[0], 1) ^ gmul(tmp[1], 1) ^ gmul(tmp[2], 2) ^ gmul(tmp[3], 3);
        state[i*4+3] = gmul(tmp[0], 3) ^ gmul(tmp[1], 1) ^ gmul(tmp[2], 1) ^ gmul(tmp[3], 2);
    }
}

// 逆列混淆
void InvMixColumns(uint8_t* state) {
    uint8_t tmp[4];
    for (int i = 0; i < 4; i++) {
        tmp[0] = state[i*4];
        tmp[1] = state[i*4+1];
        tmp[2] = state[i*4+2];
        tmp[3] = state[i*4+3];
        
        state[i*4]   = gmul(tmp[0], 0x0e) ^ gmul(tmp[1], 0x0b) ^ gmul(tmp[2], 0x0d) ^ gmul(tmp[3], 0x09);
        state[i*4+1] = gmul(tmp[0], 0x09) ^ gmul(tmp[1], 0x0e) ^ gmul(tmp[2], 0x0b) ^ gmul(tmp[3], 0x0d);
        state[i*4+2] = gmul(tmp[0], 0x0d) ^ gmul(tmp[1], 0x09) ^ gmul(tmp[2], 0x0e) ^ gmul(tmp[3], 0x0b);
        state[i*4+3] = gmul(tmp[0], 0x0b) ^ gmul(tmp[1], 0x0d) ^ gmul(tmp[2], 0x09) ^ gmul(tmp[3], 0x0e);
    }
}

// 轮密钥加
void AddRoundKey(uint8_t* state, const uint8_t* RoundKey) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= RoundKey[i];
    }
}

// AES加密
void AES_encrypt(uint8_t* state, const uint8_t* RoundKey) {
    // 初始轮密钥加
    AddRoundKey(state, RoundKey);

    // 9轮主循环
    for (int round = 1; round < Nr; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, RoundKey + round * Nb * 4);
    }

    // 最终轮
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, RoundKey + Nr * Nb * 4);
}

// AES解密
void AES_decrypt(uint8_t* state, const uint8_t* RoundKey) {
    // 初始轮密钥加(使用最后一轮密钥)
    AddRoundKey(state, RoundKey + Nr * Nb * 4);

    // 9轮主循环(从Nr-1轮开始)
    for (int round = Nr-1; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, RoundKey + round * Nb * 4);
        InvMixColumns(state);
    }

    // 最终轮
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, RoundKey);
}

// 测试AES性能
void test_aes_performance() {
    uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t roundKey[176];
    uint8_t state[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

    // 密钥扩展
    KeyExpansion(roundKey, key);

    // 测试加密性能
    clock_t start = clock();
    for (int i = 0; i < 10000; i++) {
        AES_encrypt(state, roundKey);
    }
    clock_t end = clock();
    double encrypt_time = (double)(end - start) / CLOCKS_PER_SEC;
    printf("加密10000次耗时: %f秒\n", encrypt_time);
    double encrypt_speed;
    encrypt_speed = 10000*128 / (1024*encrypt_time);
    printf("加密算法速率为: %f Kb/s\n", encrypt_speed);

    // 测试解密性能
    start = clock();
    for (int i = 0; i < 10000; i++) {
        AES_decrypt(state, roundKey);
    }
    end = clock();
    double decrypt_time = (double)(end - start) / CLOCKS_PER_SEC;
    printf("解密10000次耗时: %f秒\n", decrypt_time);
    double decrypt_speed;
    decrypt_speed = 10000*128 / (1024*decrypt_time);
    printf("解密算法速率为: %f Kb/s\n", decrypt_speed);
}

int main() {
    // printf("AES算法性能测试:\n");

    // test_aes_performance();

    printf("========================================\n");
    printf("                                        \n");
    printf("      ★ AES TOOL - AES加解密工具 ★      \n");
    printf("                                        \n");
    printf("       By.Hongchuan No.24020012         \n");
    printf("     https://github.com/redtecher       \n");
    printf("                                        \n");
    printf("========================================\n");
    printf(" 1. AES加密\n");
    printf(" 2. AES解密\n");
    printf(" 3. 性能测试\n");
    printf(" 4. 退出\n");
    
    
    while(1){
        printf("请输入选项: ");
        int choice;
        scanf("%d", &choice);
        switch (choice) {
            case 1: {
                uint8_t key[16], plaintext[16], ciphertext[16];

                /*
                测试密钥:2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
                测试明文:32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
                加密后的密文：39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
                */
                printf("请输入16字节的密钥(以空格分隔): ");
                for (int i = 0; i < 16; i++) {
                    scanf("%hhx", &key[i]);
                }
                printf("密钥为: ");
                for (int i = 0; i < 16; i++) {
                    printf("%02x ", key[i]);
                }
                printf("\n");
                printf("请输入16字节的明文(以空格分隔): ");
                for (int i = 0; i < 16; i++) {
                    scanf("%hhx", &plaintext[i]);
                }
                uint8_t roundKey[176];
                KeyExpansion(roundKey, key);
                AES_encrypt(plaintext, roundKey);
                printf("加密后的密文: ");
                for (int i = 0; i < 16; i++) {
                    printf("%02x ", plaintext[i]);
                }
                printf("\n");
                break;
            }
            case 2: {
                uint8_t key[16], ciphertext[16], plaintext[16];
                printf("请输入16字节的密钥(以空格分隔): ");
                for (int i = 0; i < 16; i++) {
                    scanf("%hhx", &key[i]);
                }
                printf("请输入16字节的密文(以空格分隔): ");
                for (int i = 0; i < 16; i++) {
                    scanf("%hhx", &ciphertext[i]);
                }
                uint8_t roundKey[176];
                KeyExpansion(roundKey, key);
                AES_decrypt(ciphertext, roundKey);
                printf("解密后的明文: ");
                for (int i = 0; i < 16; i++) {
                    printf("%02x ", ciphertext[i]);
                }
                printf("\n");
                break;
            }
            case 3:
                test_aes_performance();
                break;
            case 4:
                exit(0);
            default:
                printf("无效选项\n");
        }
        printf("按任意键继续...\n");
        getchar(); 
        getchar(); 
        
    }

    
    return 0;
}
