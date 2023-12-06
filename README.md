# File Encryption and Signing Software

This project is developed for COMP 4441 Cybersecurity:

A data (file) encryption & signing software with English user interface, using Public Key Infrastructure (PKI).
It is a web-based application. 
Hash (SHA-512), symmetric encryption(AES) and asymmetric encryption(RSA) were all used in project.
Keys (public and private key) for each user are being created first.

User A will upload the file and use the options on the screen; 
- Either, only sign the file,
- or, it will just encrypt the file (symmetrical encryption),
- or, it will both sign and encrypt the file.
- 

User B will select the file from the screen menu that is transmitted to her / him from User A and using the instructions provided by the application on the screen;

- Either, open the file and confirm that it came from A, i.e. validate signature,
- or, if the file is only symmetrically encrypted, it will be able to decrypt and open and read the file,
- or, if A has both signed and encrypted the file, it will be able to decrypt the file, open and read it, and verify that it came from A, i.e. verify the signature.
