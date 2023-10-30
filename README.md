## Building

Run the following command to build the program:
```sh
make
```

## Execution

Run the following command to encrypt `plaintext1.txt` with `key1.txt`:
```sh
 ./a3-program plaintext1.txt key1.txt
```

## Testing

The key files:
- test1key.txt
- test2key.txt
- test3key.txt

Along with the plain-text files:
- test1plaintext.txt
- test2plaintext.txt
- test3plaintext.txt

are provided for testing purposes.

## Expectations
At a mininum, you should implement separates routines to perform the following
operations (I’m using the names from the FIPS document):
- `SubBytes()`, `InvSubBytes()` that performs the s-box substitutions.
- `KeyExpansion()` that expands the input key into the 11 round keys.
- `ShiftRows()`, `InvShiftRows()` that shifts the rows.
- `MixColumns()`, `InvMixColumns()` that does the matrix multiplication in GF(256).

You should also have a routines for the encryption and decryption algorithms (`encrypt()`, `decrypt()`).
Please use the names provided above to make your code easier to read and grade.