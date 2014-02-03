'''Transfer a file very simply with encryption.
'''
import random
import argparse
import getpass
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import ARC4
import json
import http.server
import socketserver
import urllib.request
import tempfile

SALT = '''aD'T&,\L}u]Ghju[vGTuWxM{1,W]86a,Qb3OO/0eS$1}7cDmA[o61?#?sLF^\B|&}~vs{skgAhkb,=)qY9*xJQ.I9z6JEUbKkP1&$:j%5mHAv=Cp6Hw]bXN8NgE5HL1sRl%%,WS!"|;Z&D{=KO4\`z+/!0%&1@awanH"Z4c-hhd1"qrVr!~a:v}Et*kO7;@B@EipP.+RuDb]z$#QwRn25Ft_>+fG},*$$NEpR|)muq?e6q&>j~,1Gj{IdecLtDzSSyK2z8wWH'Q]<&8P~'QIlX|~PY*]=sQakDO55}lmFehH'''


class RandomKey(object):
    def __init__(self):
        key_length = 8
        rand = random.SystemRandom()
        self.randomkey = ''.join([str(rand.randint(0,9)) for i in range(8)])
    def get(self):
        return self.randomkey


class CryptKey(object):
    def __init__(self, randomkey, psk, salt):
        self.cryptkey = hashlib.sha512((randomkey+psk+salt).encode()).hexdigest()
    def get(self):
        return self.cryptkey


class Cipher(object):
    key_length = 32
    @classmethod
    def encrypt(self, key, data):
        iv = Random.new().read(AES.block_size)
        key = key[:self.key_length]

        #padding
        data_len = len(data)
        sep_len = AES.block_size
        if data_len < sep_len:
            padding_len = sep_len - data_len
        else:
            padding_len = sep_len - data_len % sep_len
        data += Random.new().read(padding_len)

        cipher = AES.new(key, AES.MODE_CBC,iv)
        encrypted_data = iv + cipher.encrypt(data)
        return padding_len, encrypted_data

    @classmethod
    def decrypt(self, key, padding_len, encrypted_data):
        iv = encrypted_data[:AES.block_size]
        key = key[:self.key_length]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = cipher.decrypt(encrypted_data)[AES.block_size:-padding_len]
        return data


def make_tmpfilename(filename):
    return hashlib.sha1(filename.encode()).hexdigest()[:10]

def send(filename):
    randomkey = getpass.getpass('RandomKey:')
    if not len(randomkey) == 8:
        print('RandomKey must be 8digits')
        exit()
    psk = getpass.getpass('Pre Shared Key(Optional):')
    cryptkey = CryptKey(randomkey, psk, SALT).get()
    filedata = open(filename,'rb').read()
    tmpfilename = make_tmpfilename(randomkey)

    padding_len, crypted_data = Cipher.encrypt(cryptkey, filedata)
    
    with open(tmpfilename, 'wb') as f:
        f.write(crypted_data)
    
    #write metadata
    metadata = json.dumps({'filename':filename, 'padding_len':padding_len})
    nonce = Random.new().read(16)
    tempkey = hashlib.sha1(nonce + randomkey.encode()).hexdigest()
    encrypted_metadata = nonce + ARC4.new(tempkey).encrypt(metadata)
    with open(tmpfilename+'_data', 'wb') as f:
        f.write(encrypted_metadata)

    #run server
    PORT = 8090
    Handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", PORT), Handler)
    httpd.serve_forever()
    print('Waiting...')
    
def receive():
    randomkey = RandomKey().get()
    print('RandomKey:{}'.format(randomkey))
    psk = getpass.getpass('Pre Shared Key(Optional):')
    cryptkey = CryptKey(randomkey, psk, SALT).get()
    tmpfilename = make_tmpfilename(randomkey)
    
    ip_addr = input('IPaddr: ')
    #read metadata
    PORT = 8090
    metadata_uri ='http://{}:{}/{}'.format(ip_addr, PORT, tmpfilename+'_data')
    encrypted_metadata = urllib.request.urlopen(metadata_uri).read()
    nonce = encrypted_metadata[:16]
    tempkey = hashlib.sha1(nonce + randomkey.encode()).hexdigest()
    metadata = ARC4.new(tempkey).decrypt(encrypted_metadata[16:]).decode()
    filename = json.loads(metadata)['filename']
    padding_len = json.loads(metadata)['padding_len']

    #read data
    data_uri = 'http://{}:{}/{}'.format(ip_addr, PORT, tmpfilename)
    crypted_data = urllib.request.urlopen(data_uri).read()

    data = Cipher.decrypt(cryptkey, padding_len, crypted_data)
    with open(filename, 'wb') as f:
        f.write(data)
    
    print('Receiving complete: {}({}Bytes)'.format(filename, len(data)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-s', '--send', metavar='FILENAME')
    args = parser.parse_args()
    if args.send:
        send(args.send)
    else:
        receive()

