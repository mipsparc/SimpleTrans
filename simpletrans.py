'''Transfer a file very simply with encryption.
'''
import random
import argparse
import getpass
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import json
import http.server
import socketserver
import urllib.request

SALT = '''aD'T&,\L}u]Ghju[vGTuWxM{1,W]86a,Qb3OO/0eS$1}7cDmA[o61?#?sLF^\B|&}~vs{skgAhkb,=)qY9*xJQ.I9z6JEUbKkP1&$:j%5mHAv=Cp6Hw]bXN8NgE5HL1sRl%%,WS!"|;Z&D{=KO4\`z+/!0%&1@awanH"Z4c-hhd1"qrVr!~a:v}Et*kO7;@B@EipP.+RuDb]z$#QwRn25Ft_>+fG},*$$NEpR|)muq?e6q&>j~,1Gj{IdecLtDzSSyK2z8wWH'Q]<&8P~'QIlX|~PY*]=sQakDO55}lmFehH'''


class RandomKey(object):
    def __init__(self):
        key_length = 8
        rand = random.SystemRandom()
        self.randomkey = ''.join([str(rand.randint(0,9)) for i in range(8)])
    def get(self):
        return self.randomkey


class EncryptKey(object):
    def __init__(self, randomkey, psk, salt):
        self.encryptkey = hashlib.sha256((randomkey+psk+salt).encode()).digest()
    def get(self):
        return self.encryptkey


class Cipher(object):
    @classmethod
    def encrypt(self, key, data):
        iv = Random.new().read(AES.block_size)

        #padding
        data_len = len(data)
        sep_len = AES.block_size
        if data_len < sep_len:
            padding_len = sep_len - data_len
        else:
            padding_len = sep_len - data_len % sep_len
        data += b' ' * padding_len

        cipher = AES.new(key, AES.MODE_CBC,iv)
        encrypted_data = iv + cipher.encrypt(data)
        return padding_len, encrypted_data

    @classmethod
    def decrypt(self, key, padding_len, encrypted_data):
        iv = encrypted_data[:AES.block_size]
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
            self.wfile.write(transfer.encrypted_transdata)
            requested = True
        elif req_filename == transfer.tmpfilename+'_data':
            self.wfile.write(transfer.encrypted_transmetadata)

    def do_HEAD(self):
        pass


class Transfer(object):
    def __init__(self, SALT, filename=None):
        self.SALT = SALT
        self.filename = filename

    def get_tmpfilename(self):
        self.tmpfilename =  hashlib.sha1(self.randomkey.encode()).hexdigest()[:10]

    def get_str_padding(self, padding_len):
        str_padding_len = str(padding_len)
        if len(str_padding_len)==1:
            str_padding_len = '0' + str_padding_len
        return str_padding_len

    def get_padding(self, str_padding_len):
        if str_padding_len[0]=='0':
            padding_len = int(str_padding_len[1])
        else:
            padding_len = int(str_padding_len)
        return padding_len


    def send(self):
        global requested
        self.randomkey = getpass.getpass('RandomKey:')
        if not len(self.randomkey) == 8:
            print('RandomKey must be 8digits')
            exit()
        psk = getpass.getpass('Pre Shared Key(Optional):')
        encryptkey = EncryptKey(self.randomkey, psk, self.SALT).get()
        filedata = open(self.filename,'rb').read()
        self.get_tmpfilename()

        padding_len, encrypted_data = Cipher.encrypt(encryptkey, filedata)
        str_padding_len = self.get_str_padding(padding_len)
        self.encrypted_transdata = str_padding_len.encode() + encrypted_data
        
        #write metadata
        hash_data = hashlib.sha512(filedata).hexdigest()
        metadata = json.dumps({'filename':self.filename, 'hash':hash_data}).encode()
        meta_padding_len, encrypted_metadata = Cipher.encrypt(encryptkey, metadata)
        str_meta_padding_len = self.get_str_padding(meta_padding_len)
        self.encrypted_transmetadata = str_meta_padding_len.encode() + encrypted_metadata

        #run server
        PORT = 8090
        socketserver.TCPServer.allow_reuse_address = True
        httpd = socketserver.TCPServer(("", PORT), TransHandler)
        while not requested:
            httpd.handle_request()
        print('done')
    
    def receive(self):
        self.randomkey = RandomKey().get()
        print('RandomKey:{}'.format(self.randomkey))
        psk = getpass.getpass('Pre Shared Key(Optional):')
        encryptkey = EncryptKey(self.randomkey, psk, self.SALT).get()
        self.get_tmpfilename()
        
        ip_addr = input('IPaddr: ')
        #read metadata
        PORT = 8090
        metadata_uri ='http://{}:{}/{}'.format(ip_addr, PORT, self.tmpfilename+'_data')
        encrypted_transmetadata = urllib.request.urlopen(metadata_uri).read()
        encrypted_metadata = encrypted_transmetadata[2:]
        str_meta_padding_len = encrypted_transmetadata[:2]
        meta_padding_len = self.get_padding(str_meta_padding_len)
        metadata = Cipher.decrypt(
                        encryptkey, meta_padding_len,encrypted_metadata).decode()
        
        self.filename = json.loads(metadata)['filename']
        hash_data = json.loads(metadata)['hash']

        #read data
        data_uri = 'http://{}:{}/{}'.format(ip_addr, PORT, self.tmpfilename)
        encrypted_transdata = urllib.request.urlopen(data_uri).read()
        encrypted_data = encrypted_transdata[2:]
        str_padding_len = encrypted_transdata[:2]
        padding_len = self.get_padding(str_padding_len)
        
        data = Cipher.decrypt(encryptkey, padding_len, encrypted_data)

        hash_received = hashlib.sha512(data).hexdigest()
        if not hash_received == hash_data:
           print('Validation check failed!')
           exit()

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

