crypter - jasondbertman@gmail.com
=======
Uses AES to run encrypted shellcode using Python and ctypes

CodeSection.py 
Contains encrypted shellcode (encrypted by ShellcodeEncrypter.py) and the ctypes functions neccessary to execute it. It gets detected in AV if not encrypted by...

EncryptCodeSection.py
Calls an encryptFile funtion (in crypt.py) that drops the "CodeSection" file. This file is encrypted and not detected by AV.

ShellcodeEncrypter.py
Used to encrypt shellcode. Not exactly neccessary, but useful if you're paranoid about static analysis.

stub.py
Decrypts "CodeSection" and runs the returned file in memory. 
