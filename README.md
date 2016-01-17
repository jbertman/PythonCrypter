Python Crypter
=======
Uses AES to run encrypted shellcode using Python and ctypes

`CodeSection.py` 
Contains encrypted shellcode (encrypted by ShellcodeEncrypter.py) and the ctypes functions neccessary to execute it. It gets detected in AV if not encrypted by...

`EncryptCodeSection.py`
Calls an encryptFile funtion (in crypt.py) that drops the "CodeSection" file. This file is encrypted and not detected by AV.

`ShellcodeEncrypter.py`
Used to encrypt shellcode. Not exactly neccessary, but useful if you're paranoid about static analysis.

`stub.py`
Decrypts "CodeSection" and runs the returned file in memory. 

This can all be packed into an executable with PyInstaller. Be warned that this is scan-time undetectable, NOT run-time undetectable. The current shellcode in the scripts runs calc.exe. Feel free to change it to whatever you want.

NOTE: This is just a PoC, the crypto functions use a static string with a random value that is embedded in the shellcode. 
