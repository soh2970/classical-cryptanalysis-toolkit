# Classical Cryptanalysis Toolkit
## Overview
This project implements multiple classical cryptanalysis techniques for breaking historical encryption schemes. The toolkit applies statistical analysis, frequency analysis, and known cryptanalytic attacks to recover plaintext without prior knowledge of the encryption keys.

The project demonstrates how weaknesses in classical ciphers and improper key management can be exploited using algorithmic approaches.


## Implemented Techniques
### Monoalphabetic Substitution Cipher
Implemented frequency analysis to recover substitution mappings and decrypt ciphertext using English letter frequency.

### Vigenère Cipher Cryptanalysis
Recovered Vigenère keys by:
- Estimating key length using the Index of Coincidence
- Applying Chi-Squared frequency analysis
- Decrypting ciphertext using the recovered key

### Extended Vigenère Cipher
Adapted the Vigenère attack to an extended alphabet, including spaces, demonstrating generalized frequency-based cryptanalysis.

### One-Time Pad Reuse Attack
Implemented crib dragging and space analysis to recover plaintext from multiple ciphertexts encrypted with a reused one-time pad.


## Skills Demonstrated
- Python
- Cryptanalysis
- Classical Cryptography
- Frequency Analysis
- Index of Coincidence
- Chi-Squared Analysis
- One-Time Pad Analysis
- XOR Operations
- Algorithm Design


## Technologies
- Python 3
- Statistical Analysis
- Frequency Analysis
- XOR Cryptanalysis


## Project Structure
```
classical-cryptanalysis-toolkit/
│
├── substitution_cipher.py
├── vigenere_cipher.py
├── extended_vigenere_cipher.py
├── otp_reuse_attack.py
├── README.md
└── LICENSE
```


## Learning Outcomes
This project strengthened my understanding of classical cryptographic systems and practical cryptanalysis techniques. By implementing statistical attacks and exploiting key reuse, I gained hands-on experience with the principles that influenced the design of modern secure cryptographic systems.


## Disclaimer
This repository is intended for educational purposes to demonstrate historical cryptographic attacks and security concepts.
