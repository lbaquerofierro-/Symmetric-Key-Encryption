#This programs receives a file as input and encrypts it using AES 
#In addition it lets the user specify the operation mode
#The password uses PBKDF secure key derivation function

import os, sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
from Crypto.Util import Counter
from Crypto.Hash import SHA256
import getpass #Getpass is used so that the password is not echoed


#store file size (truncate in CBC mode)
global fileSize

def encrypt(password, fileName, mode):
    blockSize = AES.block_size
    chunkSize = blockSize * 1024
    outputFile = "(encrypted)"+fileName
    fileSize = str(os.path.getsize(fileName)).zfill(blockSize) 

    #generate random IV
    IV = Random.new().read(blockSize)
    #if CTR mode is selected
    nonce = IV[0:8]
    #Generate random salt
    salt = Random.new().read(16)
    #Parse password
    key = keyFunction(password, salt)    
    #set mode of operation
    if mode == "CTR":
        encryptor = setMode(key, mode, nonce)
    else:
        encryptor = setMode(key, mode, IV)    

    #Read file chunks
    with open (fileName, 'rb') as inFile:
        with open(outputFile, 'wb') as outFile:
            outFile.write(fileSize)
            outFile.write(salt)
            outFile.write(IV)

            #while !eof
            while True:
                chunk = inFile.read(chunkSize)

                if len(chunk) == 0:
                    break
                #add paddding for CBC mode
                elif ((len(chunk) % 16 != 0) and (mode == "CBC" or mode == "OFB")): 
                    chunk += ' ' * (16-(len(chunk) % 16))
                #write encrypted file
                outFile.write(encryptor.encrypt(chunk))
    os.remove(fileName)

def decrypt(password, fileName, mode):
    blockSize = AES.block_size
    chunkSize = blockSize * 1024    
    outputFile = fileName[11:] 
   

    with open(fileName, 'rb') as inFile:
        fileSize = long(inFile.read(16))
        fileSize = long(fileSize)
        #read IV (first 16 bytes)
        salt = inFile.read(16)
        IV = inFile.read(blockSize) 
        #if CTR mode is selected
        nonce = IV[0:8] 
        key = keyFunction(password, salt)
        if mode == "CTR":
            decryptor = setMode(key, mode, nonce)
        else:
            decryptor = setMode(key, mode, IV)       
        
        with open(outputFile, 'wb') as outFile:
            while True:
                #read every chunk after IV
                chunk = inFile.read(chunkSize)

                if len(chunk) == 0:
                    break
                #write decrypted file
                outFile.write(decryptor.decrypt(chunk))
            #Remove padding
            outFile.truncate(fileSize)
    os.remove(fileName)

#This function uses a secure key derivatio function to salt the password (PBKDF)
def keyFunction(password, salt):
    keySize = 16
    iterations = 1000
    derivedKey = PBKDF2(password, salt, keySize, iterations)
    return derivedKey

#This function sets the mode
def setMode(key, mode, IV):
    if mode == "CBC":
        object_ = AES.new(key, AES.MODE_CBC, IV)
    elif mode == "CFB":
        object_ = AES.new(key, AES.MODE_CFB, IV) 
    elif mode == "OFB":
        object_ = AES.new(key, AES.MODE_OFB, IV)
    elif mode == "CTR":
        nonce = Random.new().read(8)
        object_ = AES.new(key, AES.MODE_CTR, counter=Counter.new(64, prefix=IV))
    return object_


def Main():
    choice = raw_input("Would you like to (E)ncrypt or (D)ecrypt?: ")
    if choice in ['E', 'D']:
        mode = raw_input("Enter mode CBC/CFB/OFB/CTR/ECB*: ")
        if mode in ["CBC", "CFB", "OFB", "CTR", "ECB"]:
            if mode == "ECB":
                sys.exit("DISCLAIMER: Given that not enough responsability is being used while using this program, it will terminate")
            else:
                if choice == 'E':
                    filename = raw_input("File to encrypt: ")
                    #password = raw_input("Password: ")
                    if os.path.exists(filename):
                        password = getpass.getpass()
                        encrypt(password, filename, mode)
                    else:
                        sys.exit("File does not exist, closing...")
                    print "Done."
                elif choice == 'D':
                    filename = raw_input("File to decrypt: ")
                    if os.path.exists(filename):
                        password = getpass.getpass()
                        decrypt(password, filename, mode)
                    else:
                        sys.exit("File does not exist, closing...")
                    print "Done."
                else:
                    sys.exit("No mode selected, closing...")
        else:
            sys.exit("No mode selected, closing...")
    else:
        sys.exit("No Option selected, closing...")
        

if __name__ == '__main__':
    Main()