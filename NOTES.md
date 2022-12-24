In https://github.com/rajohns08/corecrypto/blob/master/ccec/crypto_test/crypto_test_keyroll.c the private key d is 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b

Multiplying d by G gives a point (0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21, 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34)
The public key is these two values
The private key is the three values (x, y) and d

Note then that the value in the keys file is the _private_ key, d.