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

// Macros for accessing state bytes
#define s0 s[(i * 4)]
#define s1 s[(i * 4) + 1]
#define s2 s[(i * 4) + 2]
#define s3 s[(i * 4) + 3]

// Round constants for key expansion seen on slide 218 (FIPS 197 Table 5)
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
    // Simple base case
    if (b == 0x01)
    {
        return a;
    }

    // Rule to multiply by 0x02
    if (b == 0x02)
    {
        return (a & 0x80) ? ((a << 1) ^ 0x1b) : (a << 1);
    }

    // Multiplication by 0x03 is just multiplication by 0x02 and addition
    if (b == 0x03)
    {
        return gf_multiply(a, 0x02) ^ a;
    }

    // Multiplication by a power of 2 can be done recursively
    if (b == 0x04 || b == 0x08 || b == 0x10 || b == 0x20 || b == 0x40 || b == 0x80)
    {
        return gf_multiply(gf_multiply(a, 0x02), b >> 1);
    }

    // {0B} = {08} ^ {02} ^ {01}
    if (b == 0x0B)
    {
        return gf_multiply(a, 0x08) ^ gf_multiply(a, 0x02) ^ a;
    }

    // {0E} = {08} ^ {04} ^ {02}
    if (b == 0x0E)
    {
        return gf_multiply(a, 0x08) ^ gf_multiply(a, 0x04) ^ gf_multiply(a, 0x02);
    }

    // {0D} = {08} ^ {04} ^ {01}
    if (b == 0x0D)
    {
        return gf_multiply(a, 0x08) ^ gf_multiply(a, 0x04) ^ a;
    }

    // {09} = {08} ^ {01}
    if (b == 0x09)
    {
        return gf_multiply(a, 0x08) ^ a;
    }

    // This is all we need for AES
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

// Print state (4x4 matrix) in line format
void print_state(uint8_t *state)
{
    for (int i = 0; i < 16; i++)
    {
        printf("%02x", state[i]);
    }
    printf("\n");
}

// Print state in format specified in assignment document
void print_state_output(uint8_t *state)
{
    for (int i = 0; i < 4; i++)
    {
        printf("%02x  %02x  %02x  %02x", state[i * 4], state[i * 4 + 1], state[i * 4 + 2], state[i * 4 + 3]);
        printf("     ");
    }
    printf("\n");
}

// Print state (4x4 matrix) in block format
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

// Load 16 bytes from a file into a buffer
void load_from_file(char *filename, uint8_t buffer[16])
{
    // Open file
    FILE *f = fopen(filename, "r");

    // Check for errors
    if (f == NULL)
    {
        printf("Error: could not open file %s\n", filename);
        exit(1);
    }

    // Read in 16 hex bytes from file
    for (int i = 0; i < 16; i++)
    {
        uint8_t temp;
        fscanf(f, "%02hhx", &temp);

        // Write to buffer
        buffer[i] = temp;
    }
}

// Perform substitution on each byte in the state
void sub_bytes(uint8_t *state)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] = sbox[state[i]];
    }
}

// Inverse substitution on each byte in the state
void inv_sub_bytes(uint8_t *state)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] = invsbox[state[i]];
    }
}

// Shift rows in the state
void shift_rows(uint8_t *state)
{
    // Persist original state to avoid overlap
    uint8_t temp[16];
    memcpy(temp, state, 16);

    // Shift each row to the left by the row number
    for (int i = 0; i < 16; i++)
    {
        state[i] = temp[((i - (i % 4)) + (i % 4) * 5) % 16];
    }
}

// Inverse shift rows in the state
void inv_shift_rows(uint8_t *state)
{
    // Persist original state to avoid overlap
    uint8_t temp[16];
    memcpy(temp, state, 16);

    // Shift each row to the right by the row number
    for (int i = 0; i < 16; i++)
    {
        state[i] = temp[((i - (i % 4)) + (16 - ((i % 4) * 3))) % 16];
    }
}

// Apply the given key (4x 32-bit words) to the state
void apply_key(uint8_t *state, uint32_t key[4])
{
    // Buffer to store key bytes
    uint8_t temp[16];

    // Convert key to bytes
    word_to_bytes(*key, &temp[0]);
    word_to_bytes(*(key + 1), &temp[4]);
    word_to_bytes(*(key + 2), &temp[8]);
    word_to_bytes(*(key + 3), &temp[12]);

    // XOR each byte in the state with the corresponding byte in the key
    for (int i = 0; i < 16; i++)
    {
        state[i] ^= temp[i];
    }
}

// Mix columns in the state
void mix_columns(uint8_t *state)
{
    // Persist original state to avoid overlap
    uint8_t s[16];
    memcpy(s, state, 16);

    // Iterate over each column
    for (int i = 0; i < 4; i++)
    {
        // s0 = {02}*s0 + {03}*s1 + s2 + s3
        state[(i * 4)] = gf_multiply(s0, 0x02) ^ gf_multiply(s1, 0x03) ^ s2 ^ s3;
        // s1 = s0 + {02}*s1 + {03}*s2 + s3
        state[(i * 4) + 1] = s0 ^ gf_multiply(s1, 0x02) ^ gf_multiply(s2, 0x03) ^ s3;
        // s2 = s0 + s1 + {02}*s2 + {03}*s3
        state[(i * 4) + 2] = s0 ^ s1 ^ gf_multiply(s2, 0x02) ^ gf_multiply(s3, 0x03);
        // s3 = {03}*s0 + s1 + s2 + {02}*s3
        state[(i * 4) + 3] = gf_multiply(s0, 0x03) ^ s1 ^ s2 ^ gf_multiply(s3, 0x02);
    }
}

// Inverse mix columns in the state
void inv_mix_columns(uint8_t *state)
{
    // Persist original state to avoid overlap
    uint8_t s[16];
    memcpy(s, state, 16);

    // Iterate over each column
    for (int i = 0; i < 4; i++)
    {
        // s0 = {0E}*s0 + {0B}*s1 + {0D}*s2 + {09}*s3
        state[(i * 4)] = gf_multiply(s0, 0x0E) ^ gf_multiply(s1, 0x0B) ^ gf_multiply(s2, 0x0D) ^ gf_multiply(s3, 0x09);
        // s1 = {09}*s0 + {0E}*s1 + {0B}*s2 + {0D}*s3
        state[(i * 4) + 1] = gf_multiply(s0, 0x09) ^ gf_multiply(s1, 0x0E) ^ gf_multiply(s2, 0x0B) ^ gf_multiply(s3, 0x0D);
        // s2 = {0D}*s0 + {09}*s1 + {0E}*s2 + {0B}*s3
        state[(i * 4) + 2] = gf_multiply(s0, 0x0D) ^ gf_multiply(s1, 0x09) ^ gf_multiply(s2, 0x0E) ^ gf_multiply(s3, 0x0B);
        // s3 = {0B}*s0 + {0D}*s1 + {09}*s2 + {0E}*s3
        state[(i * 4) + 3] = gf_multiply(s0, 0x0B) ^ gf_multiply(s1, 0x0D) ^ gf_multiply(s2, 0x09) ^ gf_multiply(s3, 0x0E);
    }
}

// Generate the remaining 40x 32-bit words from the given key stored in the first 4x 32-bit words
void generate_keys(uint32_t keys[44])
{
    // 10x rounds of key generation
    for (int round = 1; round < 11; round++)
    {
        uint8_t key_bytes[4], subbed_bytes[4];

        // Rotate word
        word_to_bytes(keys[(round - 1) * 4 + 3], key_bytes);
        subbed_bytes[0] = sbox[key_bytes[1]];
        subbed_bytes[1] = sbox[key_bytes[2]];
        subbed_bytes[2] = sbox[key_bytes[3]];
        subbed_bytes[3] = sbox[key_bytes[0]];

        // Using 4x 32-bit words to match the NIST document
        keys[round * 4] = keys[(round - 1) * 4] ^ bytes_to_word(subbed_bytes) ^ rcon[round];
        keys[round * 4 + 1] = keys[(round - 1) * 4 + 1] ^ keys[round * 4];
        keys[round * 4 + 2] = keys[(round - 1) * 4 + 2] ^ keys[round * 4 + 1];
        keys[round * 4 + 3] = keys[(round - 1) * 4 + 3] ^ keys[round * 4 + 2];
    }
}

// Encrypt the plaintext using the given key and store the result in ciphertext
void encrypt(uint8_t *plaintext, uint8_t *key, uint8_t *ciphertext)
{
    uint8_t state[16];
    uint32_t keys[44];

    // Load plaintext into state
    memcpy(state, plaintext, 16);

    // Load key into key expansion array
    keys[0] = bytes_to_word(&key[0]);
    keys[1] = bytes_to_word(&key[4]);
    keys[2] = bytes_to_word(&key[8]);
    keys[3] = bytes_to_word(&key[12]);

    // Expand key to 44x 32-bit words
    generate_keys(keys);

    // Print key schedule for assignment specifications
    printf("Key Schedule:\n");
    for (int key = 0; key < 11; key++)
    {
        printf("%08x,%08x,%08x,%08x\n", keys[key * 4], keys[key * 4 + 1], keys[key * 4 + 2], keys[key * 4 + 3]);
    }
    printf("\n");

    // Print header and initial state (plaintext)
    printf("ENCRYPTION PROCESS\n");
    printf("------------------\n");
    printf("Plain Text:\n");
    print_state_output(state);
    printf("\n");

    // Perform encryption routine as specified in slides
    apply_key(state, &keys[0]);
    for (int round = 1; round < 11; round++)
    {
        sub_bytes(state);
        shift_rows(state);
        if (round <= 9)
        {
            mix_columns(state);

            printf("State after call %d to MixColumns()\n", round);
            printf("-------------------------------------\n");
            print_state_output(state);
            printf("\n");
        }
        apply_key(state, &keys[round * 4]);
    }

    // Print result state (ciphertext)
    printf("CipherText:\n");
    print_state_output(state);
    printf("\n");

    // Store ciphertext in output buffer
    memcpy(ciphertext, state, 16);
}

// Decrypt the ciphertext using the given key and store the result in plaintext
void decrypt(uint8_t *ciphertext, uint8_t *key, uint8_t *plaintext)
{
    uint8_t state[16];
    uint32_t keys[44];

    // Load ciphertext into state
    memcpy(state, ciphertext, 16);

    // Load key into key expansion array
    keys[0] = bytes_to_word(&key[0]);
    keys[1] = bytes_to_word(&key[4]);
    keys[2] = bytes_to_word(&key[8]);
    keys[3] = bytes_to_word(&key[12]);

    // Expand key to 44x 32-bit words
    generate_keys(keys);

    // Print header and initial state (ciphertext)
    printf("DECRYPTION PROCESS\n");
    printf("------------------\n");
    printf("CipherText:\n");
    print_state_output(state);
    printf("\n");

    // Perform decryption routine as specified in slides (reverse order of encryption)
    apply_key(state, &keys[40]);
    for (int round = 9; round >= 0; round--)
    {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        apply_key(state, &keys[round * 4]);
        if (round != 0)
        {
            inv_mix_columns(state);
            printf("State after call %d to InvMixColumns()\n", 10 - round);
            printf("----------------------------------------------\n");
            print_state_output(state);
            printf("\n");
        }
    }

    // Print result state (plaintext)
    printf("Plaintext:\n");
    print_state_output(state);
    printf("\n");

    // Store plaintext in output buffer
    memcpy(plaintext, state, 16);
}

int main(int argc, char *argv[])
{
    uint8_t plaintext[16], ciphertext[16], decrypted[16], key[16];

    // Check for correct number of arguments
    if (argc != 3)
    {
        printf("Usage: %s <plaintext file> <key file>\n", argv[0]);
        return 1;
    }

    // Load plaintext and key from files
    load_from_file(argv[1], plaintext);
    load_from_file(argv[2], key);

    // Print plaintext for assignment specifications
    printf("Plaintext\n");
    print_state(plaintext);

    // Print key for assignment specifications
    printf("Key\n");
    print_state(key);

    // Run encryption
    encrypt(plaintext, key, ciphertext);

    // Pretty self explanatory
    printf("\n\n");

    // Run decryption
    decrypt(ciphertext, key, decrypted);

    printf("End of Processing\n");
    return 0;
}