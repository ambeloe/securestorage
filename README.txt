encrypts and decrypts byte slices provided a key

ciphertext format is as follows:

|---salt 16b---|--nonce 12b--|-----ciphertext-----|

salt and nonce are generated anew for each save operation
should be thread safe
