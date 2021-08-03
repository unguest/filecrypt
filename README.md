# filecrypt
Java program to encrypt and decrypt files using AES-256.

# How it works
When it encrypts a file, the program creates two files : a .enc which contains encrypted data and a .inf file which contains the Initialization Vector for the
AES CBC mode & the password salt.

To be able to decrypt a file, these two files are required.
