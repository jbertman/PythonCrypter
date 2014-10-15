import hashlib, os, struct
from Crypto.Cipher import AES
from StringIO import StringIO

def encrypt(shellcode):
    IV = os.urandom(16)
    salt = os.urandom(16)
    key = hashlib.sha256("nok0der" + salt).digest()
    mode = AES.MODE_CBC
    encryptor = AES.new(key, mode, IV=IV)

    mod = len(shellcode) % 16
    print "Length of shellcode is %i" % (len(shellcode))

    if mod != 0: 
        shellcode += "\x90" * (16 - mod)
        print "Padded payload with %i bytes" % (16 - mod)

    ciphertext = encryptor.encrypt(shellcode)
    payload = "%s%s%s" % (IV,salt,ciphertext)
    return payload

def encryptFile(script):
    chunksize = 64 * 1024
    IV = os.urandom(16)
    salt = os.urandom(16)
    key = hashlib.sha256("nok0der" + salt).digest()
    mode = AES.MODE_CBC
    encryptor = AES.new(key, mode, IV=IV)
    filesize = os.path.getsize(script)

    with open(script, 'rb') as infile:
        with open('codeSection', 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(IV)
            outfile.write(salt)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                    
                outfile.write(encryptor.encrypt(chunk))
                
def decryptFile(script):
    chunksize = 64 * 1024
    out = ""
    with open(script, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        IV = infile.read(16)
        salt = infile.read(16)
        key = hashlib.sha256("nok0der" + salt).digest()
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        while True:
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            out += decryptor.decrypt(chunk)
        return out

def decrypt(payload):
    IV = payload[:16]
    salt = payload[16:32]
    ciphertext = payload[32::]
    key = hashlib.sha256("nok0der" + salt).digest()
    mode = AES.MODE_CBC
    decryptor = AES.new(key, mode, IV=IV)
    plain = decryptor.decrypt(ciphertext)
    return plain

def decryptStub():
    chunksize = 64 * 1024
    out = ""
    with open("stub2.py", "rb") as data:        
        for line in data:
            if line[0] == '#':
                start = data.tell() - len(line)
                break
        data.seek(start)
        origsize = struct.unpack('<Q', data.read(struct.calcsize('Q')))[0]
        print origsize
        IV = data.read(16)
        print IV
        salt = data.read(16)
        print salt
        key = hashlib.sha256("nok0der" + salt).digest()
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        while True:
            chunk = data.read(chunksize)
            if len(chunk) == 0:
                break
            print len(chunk)
            out += decryptor.decrypt(chunk)

        return out

        
        
