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


class TransHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global requested
        self.send_response(200, 'OK')
        self.send_header('Content-type', 'html')
        self.end_headers()
        req_filename = self.path[1:]
        print('requested:'+req_filename)
        if req_filename == transfer.tmpfilename:
            self.wfile.write(transfer.crypted_data)
            requested = True
        elif req_filename == transfer.tmpfilename+'_data':
            self.wfile.write(transfer.encrypted_metadata)

    def do_HEAD(self):
        pass


class Transfer(object):
    def __init__(self, SALT, filename=None):
        self.SALT = SALT
        self.filename = filename

    def get_tmpfilename(self):
        self.tmpfilename =  hashlib.sha1(self.randomkey.encode()).hexdigest()[:10]

    def send(self):
        global requested
        self.randomkey = getpass.getpass('RandomKey:')
        if not len(self.randomkey) == 8:
            print('RandomKey must be 8digits')
            exit()
        psk = getpass.getpass('Pre Shared Key(Optional):')
        cryptkey = CryptKey(self.randomkey, psk, self.SALT).get()
        filedata = open(self.filename,'rb').read()
        self.get_tmpfilename()

        padding_len, self.crypted_data = Cipher.encrypt(cryptkey, filedata)
        
        #write metadata
        metadata = json.dumps({'filename':self.filename, 'padding_len':padding_len})
        nonce = Random.new().read(16)
        tempkey = hashlib.sha1(nonce + self.randomkey.encode()).hexdigest()
        self.encrypted_metadata = nonce + ARC4.new(tempkey).encrypt(metadata)

        #run server
        PORT = 8090
        httpd = socketserver.TCPServer(("", PORT), TransHandler)
        while not requested:
            httpd.handle_request()
        print('done')
    
    def receive(self):
        self.randomkey = RandomKey().get()
        print('RandomKey:{}'.format(self.randomkey))
        psk = getpass.getpass('Pre Shared Key(Optional):')
        cryptkey = CryptKey(self.randomkey, psk, self.SALT).get()
        self.get_tmpfilename()
        
        ip_addr = input('IPaddr: ')
        #read metadata
        PORT = 8090
        metadata_uri ='http://{}:{}/{}'.format(ip_addr, PORT, self.tmpfilename+'_data')
        encrypted_metadata = urllib.request.urlopen(metadata_uri).read()
        nonce = encrypted_metadata[:16]
        tempkey = hashlib.sha1(nonce + self.randomkey.encode()).hexdigest()
        metadata = ARC4.new(tempkey).decrypt(encrypted_metadata[16:]).decode()
        self.filename = json.loads(metadata)['filename']
        padding_len = json.loads(metadata)['padding_len']

        #read data
        data_uri = 'http://{}:{}/{}'.format(ip_addr, PORT, self.tmpfilename)
        crypted_data = urllib.request.urlopen(data_uri).read()

        data = Cipher.decrypt(cryptkey, padding_len, crypted_data)
        with open(self.filename, 'wb') as f:
            f.write(data)
        
        print('Receiving complete: {}({}Bytes)'.format(self.filename, len(data)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-s', '--send', metavar='FILENAME')
    args = parser.parse_args()
    if args.send:
        transfer = Transfer(SALT, args.send)
        requested = False
        transfer.send()
    else:
        transfer = Transfer(SALT)
        transfer.receive()

