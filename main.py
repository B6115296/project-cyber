from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from hashlib import sha256
import os
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA


# Create Keys

def create_keys(name_split):
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open(name_split+"private.key", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open(name_split+"public.key", "wb")
    file_out.write(public_key)
    file_out.close()
# -----------------------------------------------------------------------

# Sign_message
def sign_message(name_split):
    #import codecs

    file_in = open("(enc)."+name_split+".txt", "rb")
    message = file_in.read()
    file_in.close()
    key = RSA.import_key(open(name_split+'private.key').read())
    h = SHA512.new(message)

    '''
    once hashing is done, we need to create a sign object through 
    which we can sign a message
    '''

    signer=pkcs1_15.new(key)
    signature=signer.sign(h)
    #signature = pkcs1_15.new(key).sign(h)
    #signature_readable=codecs.getencoder('hex')(signature)
    #print(signature.hex())


    file_out = open(name_split+"signature.pem", "wb")
    file_out.write(signature)
    file_out.close()

    file_out = open(name_split+"message.txt", "wb")
    file_out.write(message)
    file_out.close()
# -----------------------------------------------------------------------

# verify_message

def verify_keys(name_split):
    key = RSA.import_key(open(name_split+'public.key').read())

    file_in = open(name_split+"message.txt", "rb")
    message=file_in.read()
    file_in.close()

    file_in = open(name_split+"signature.pem", "rb")
    signature=file_in.read()
    file_in.close()

    h = SHA512.new(message)

    try:
        pkcs1_15.new(key).verify(h, signature)
        print ("The signature is valid.")
        return True
    except (ValueError, TypeError):
        print ("The signature is not valid.")
        return False
# -----------------------------------------------------------------------

def encrypt(key, filename):

    chunksize = 64*1024
    outputFile = "(enc)."+filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)
    name_split = filename.split('.')

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:  # rb means read in binary
        with open(outputFile, 'wb') as outfile:  # wb means write in the binary mode
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' '*(16-(len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))
    if name_split[1] == 'txt':
        create_keys(name_split[0])
        sign_message(name_split[0])

def decrypt(key, filename):
    chunksize = 64*1024
    outputFile = "de"+filename[11:]
    name_split = filename.split('.')

    if name_split[2] == 'txt':
        if not verify_keys(name_split[1]):
            return False
            

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(filesize)

def getKey(password):
    hasher = sha256(password.encode('utf-8'))
    #file = open(filename+'_KEY', 'wb')
    #file.write(hasher.digest())
    #file.close()
    return hasher.digest()


def Main():
    while True:
        choice = int(input("1. Press '1' to encrypt file.\n2. Press '2' to decrypt file.\n3. Press '3' to exit.\nWould do you do :"))
        
        if choice == 1:
            filename = input("File to encrypt: ")
            password = input("Password: ")
            encrypt(getKey(password),filename)
            print('Done.')
            print("============================")
        elif choice == 2:
            filename = input("File to decrypt: ")
            password = input("Password: ")
            if not decrypt(getKey(password),filename):
                break
            print("Done.")
            print("============================")
        elif choice == 3:
            exit()
        else:
            print("Please select a valid option!")
            print("============================")

Main()