/**
 * @file main.c
 * @author Landon Colburn (colburnl@myumanitoba.ca)
 * @brief Assignment 3: AES FIPS 197
 * @version 1.0
 * @date 2023-11-03 (submitted)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sbox.h"

#define s0 s[(i * 4)]
#define s1 s[(i * 4) + 1]
#define s2 s[(i * 4) + 2]
#define s3 s[(i * 4) + 3]

uint32_t rcon[11] = {
    0x00000000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1b000000,
    0x36000000};

// Multiplication of 0x02, 0x03, 0x0E, 0x0B, 0x0D, and 0x09 in GF(2^8)
uint8_t gf_multiply(uint8_t a, uint8_t b)
{
    if (b == 0x01)
    {
        return a;
    }
    if (b == 0x02)
    {
        return (a & 0x80) ? ((a << 1) ^ 0x1b) : (a << 1);
    }
    if (b == 0x03)
    {
        return gf_multiply(a, 0x02) ^ a;
    }
    if (b == 0x04 || b == 0x08 || b == 0x10 || b == 0x20 || b == 0x40 || b == 0x80)
    {
        return gf_multiply(gf_multiply(a, 0x02), b >> 1);
    }
    if (b == 0x0B)
    {
        return gf_multiply(a, 0x08) ^ gf_multiply(a, 0x02) ^ a;
    }
    if (b == 0x0E)
    {
        return gf_multiply(a, 0x08) ^ gf_multiply(a, 0x04) ^ gf_multiply(a, 0x02);
    }
    if (b == 0x0D)
    {
        return gf_multiply(a, 0x08) ^ gf_multiply(a, 0x04) ^ a;
    }
    if (b == 0x09)
    {
        return gf_multiply(a, 0x08) ^ a;
    }
    printf("Error: unimplemented multiplication\n");
    exit(1);
}

// Convert a 32-bit word to a 4-byte array
void word_to_bytes(uint32_t word, uint8_t bytes[4])
{
    bytes[0] = word >> 24;
    bytes[1] = word >> 16;
    bytes[2] = word >> 8;
    bytes[3] = word;
}

// Convert a 4-byte array to a 32-bit word
uint32_t bytes_to_word(uint8_t bytes[4])
{
    return bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
}

void print_state(uint8_t *state)
{
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", state[i]);
    }
    printf("\n");
}

void print_state_block(uint8_t *state)
{
    for (int i = 0; i < 4; i++)
    {
        printf("%02x ", state[i]);
        printf("%02x ", state[i + 4]);
        printf("%02x ", state[i + 8]);
        printf("%02x", state[i + 12]);
        printf("\n");
    }
}

void load_from_file(char *filename, uint8_t buffer[16])
{
    FILE *f = fopen(filename, "r");
    if (f == NULL)
    {
        printf("Error: could not open file %s\n", filename);
        exit(1);
    }
    for (int i = 0; i < 16; i++)
    {
        uint8_t temp;
        fscanf(f, "%02hhx", &temp);
        buffer[i] = temp;
    }
}

void sub_bytes(uint8_t *state)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] = sbox[state[i]];
    }
}

void inv_sub_bytes(uint8_t *state)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] = invsbox[state[i]];
    }
}

void shift_rows(uint8_t *state)
{
    uint8_t temp[16];
    memcpy(temp, state, 16);

    for (int i = 0; i < 4; i++)
    {
        state[(i * 4) + 1] = temp[((i * 4) + 5) % 16];
        state[(i * 4) + 2] = temp[((i * 4) + 10) % 16];
        state[(i * 4) + 3] = temp[((i * 4) + 15) % 16];
    }
}

void inv_shift_rows(uint8_t *state)
{
    uint8_t temp[16];
    memcpy(temp, state, 16);

    for (int i = 0; i < 4; i++)
    {
        state[(i * 4) + 1] = temp[((i * 4) + 13) % 16];
        state[(i * 4) + 2] = temp[((i * 4) + 10) % 16];
        state[(i * 4) + 3] = temp[((i * 4) + 7) % 16];
    }
}

void apply_key(uint8_t *state, uint32_t key[4])
{
    uint8_t temp[16];

    word_to_bytes(*key, &temp[0]);
    word_to_bytes(*(key + 1), &temp[4]);
    word_to_bytes(*(key + 2), &temp[8]);
    word_to_bytes(*(key + 3), &temp[12]);

    for (int i = 0; i < 16; i++)
    {
        state[i] ^= temp[i];
    }
}

void mix_columns(uint8_t *state)
{
    uint8_t s[16];
    memcpy(s, state, 16);

    for (int i = 0; i < 4; i++)
    {
        state[(i * 4)] = gf_multiply(s0, 2) ^ gf_multiply(s1, 3) ^ s2 ^ s3;
        state[(i * 4) + 1] = s0 ^ gf_multiply(s1, 2) ^ gf_multiply(s2, 3) ^ s3;
        state[(i * 4) + 2] = s0 ^ s1 ^ gf_multiply(s2, 2) ^ gf_multiply(s3, 3);
        state[(i * 4) + 3] = gf_multiply(s0, 3) ^ s1 ^ s2 ^ gf_multiply(s3, 2);
    }
}

void inv_mix_columns(uint8_t *state)
{
    uint8_t s[16];
    memcpy(s, state, 16);

    for (int i = 0; i < 4; i++)
    {
        state[(i * 4)] = gf_multiply(s0, 0x0e) ^ gf_multiply(s1, 0x0b) ^ gf_multiply(s2, 0x0d) ^ gf_multiply(s3, 0x09);
        state[(i * 4) + 1] = gf_multiply(s0, 0x09) ^ gf_multiply(s1, 0x0e) ^ gf_multiply(s2, 0x0b) ^ gf_multiply(s3, 0x0d);
        state[(i * 4) + 2] = gf_multiply(s0, 0x0d) ^ gf_multiply(s1, 0x09) ^ gf_multiply(s2, 0x0e) ^ gf_multiply(s3, 0x0b);
        state[(i * 4) + 3] = gf_multiply(s0, 0x0b) ^ gf_multiply(s1, 0x0d) ^ gf_multiply(s2, 0x09) ^ gf_multiply(s3, 0x0e);
    }
}

void generate_keys(uint32_t keys[44])
{
    for (int round = 1; round < 11; round++)
    {
        uint8_t key_bytes[4], subbed_bytes[4];

        word_to_bytes(keys[(round - 1) * 4 + 3], key_bytes);
        subbed_bytes[0] = sbox[key_bytes[1]];
        subbed_bytes[1] = sbox[key_bytes[2]];
        subbed_bytes[2] = sbox[key_bytes[3]];
        subbed_bytes[3] = sbox[key_bytes[0]];

        keys[round * 4] = keys[(round - 1) * 4] ^ bytes_to_word(subbed_bytes) ^ rcon[round];
        keys[round * 4 + 1] = keys[(round - 1) * 4 + 1] ^ keys[round * 4];
        keys[round * 4 + 2] = keys[(round - 1) * 4 + 2] ^ keys[round * 4 + 1];
        keys[round * 4 + 3] = keys[(round - 1) * 4 + 3] ^ keys[round * 4 + 2];
    }
}

void encrypt(uint8_t *plaintext, uint8_t *key, uint8_t *ciphertext)
{
    uint8_t state[16];
    uint32_t keys[44];

    memcpy(state, plaintext, 16);

    keys[0] = bytes_to_word(&key[0]);
    keys[1] = bytes_to_word(&key[4]);
    keys[2] = bytes_to_word(&key[8]);
    keys[3] = bytes_to_word(&key[12]);

    generate_keys(keys);
    apply_key(state, &keys[0]);

    for (int round = 1; round < 11; round++)
    {
        sub_bytes(state);
        shift_rows(state);
        if (round <= 9)
        {
            mix_columns(state);
        }
        apply_key(state, &keys[round * 4]);
    }

    memcpy(ciphertext, state, 16);
}

void decrypt(uint8_t *ciphertext, uint8_t *key, uint8_t *plaintext)
{
    uint8_t state[16];
    uint32_t keys[44];

    memcpy(state, ciphertext, 16);

    keys[0] = bytes_to_word(&key[0]);
    keys[1] = bytes_to_word(&key[4]);
    keys[2] = bytes_to_word(&key[8]);
    keys[3] = bytes_to_word(&key[12]);

    generate_keys(keys);
    apply_key(state, &keys[40]);

    for (int round = 9; round >= 1; round--)
    {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        apply_key(state, &keys[round * 4]);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    apply_key(state, &keys[0]);

    memcpy(plaintext, state, 16);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <plaintext file> <key file>\n", argv[0]);
        return 1;
    }

    uint8_t plaintext[16];
    load_from_file(argv[1], plaintext);

    uint8_t key[16];
    load_from_file(argv[2], key);

    printf("Plaintext:\n");
    print_state(plaintext);

    uint8_t ciphertext[16];
    encrypt(plaintext, key, ciphertext);

    printf("Ciphertext:\n");
    print_state(ciphertext);

    uint8_t decrypted[16];
    decrypt(ciphertext, key, decrypted);

    printf("Decrypted:\n");
    print_state(decrypted);

    return 0;
}