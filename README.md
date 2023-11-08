# Simplified AES
Simplified AES (S-AES) is an educational alogrithm designed by Edward Schaefer to help students understand the structure of AES. The diagram below gives a high level overview of the
encrpytion and decryption process: 

![Screenshot from 2023-11-07 17-59-23](https://github.com/kevin-fagan/simplified-aes/assets/19915245/21d30324-f84e-44d3-aea1-2f52f0e086f2)

# Usage

```python
plaintext = 0b1011000100101110 # 16 bits
key = 0b1101101000111010 # 16 bits

ciphertext = encrypt(plaintext, key)
plaintext = decrypt(ciphertext, key)
```

# References

The PDF that explains the implemented of S-AES is included in this repository and can be found [here](https://github.com/kevin-fagan/simplified-aes/blob/main/simplified-aes.pdf).
