#!/usr/bin/env python3

'''Transfer a file very simply with encryption.
'''
import argparse
import getpass
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random
import json
import http.server
import socketserver
import urllib.request
import socket
import DiffieHellman3
import base64
import time

SALT = '''aD'T&,\L}u]Ghju[vGTuWxM{1,W]86a,Qb3OO/0eS$1}7cDmA[o61?#?sLF^\B|&}~vs
{skgAhkb,=)qY9*xJQ.I9z6JEUbKkP1&$:j%5mHAv=Cp6Hw]bXN8NgE5HL1sRl%%,WS!"|;Z&D{=KO
4\`z+/!0%&1@awanH"Z4c-hhd1"qrVr!~a:v}Et*kO7;@B@EipP.+RuDb]z$#QwRn25Ft_>+fG},*$
$NEpR|)muq?e6q&>j~,1Gj{IdecLtDzSSyK2z8wWH'Q]<&8P~'QIlX|~PY*]=sQakDO55}lmFehH'''


class RandomKey(object):
    def __init__(self):
        char_map='#$%&*+23456789=?ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz'
        key_length = 8
        self.randomkey = ''.join([random.choice(char_map) for i in \
            range(key_length)])

    def get(self):
        return self.randomkey


class GenerateKey(object):
    def __init__(self, randomkey, psk):
        hash_times = 10000
        seed = randomkey+psk+SALT
        self.hash_result = str(seed).encode()
        for i in range(hash_times):
            self.hash_result += (psk+SALT).encode()
            self.hash_result = hashlib.sha256(self.hash_result).digest()

    def get_key(self):
        diffie_key = hashlib.sha256(self.hash_result).digest()
        return diffie_key

    def get_search_id(self):
        search_id = self.hash_result[:6]
        return search_id


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

        cipher = AES.new(key, AES.MODE_CBC, iv)
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
        global finished_transfer
        global allow_ip_address

        if self.client_address[0] == allow_ip_address:
            self.send_response(200, 'OK')
            self.send_header('Content-type', 'html')
            self.end_headers()
            req_filename = self.path[1:]
            if req_filename == transfer.tmpfilename:
                print('Sending...')
                self.wfile.write(transfer.encrypted_transdata)
                finished_transfer = True
            elif req_filename == transfer.tmpfilename+'_data':
                self.wfile.write(transfer.encrypted_transmetadata)

    def do_HEAD(self):
        pass

    #be quiet!
    def log_message(self, format, *args):
        pass


class SearchHost(object):
    def __init__(self, PORT, search_id):
        self.PORT = PORT
        self.search_id = search_id
        self.ip_address = None

    def receive_node(self):
        while not self.ip_address:
            self.search()     
            try:
                self.receive_response()
            except socket.timeout:
                pass
        
    #receive node
    def search(self):
        #UDP
        search_data = hashlib.sha256(self.search_id + b'FIND').digest()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        HOST = '<broadcast>'
        sock.sendto(search_data, (HOST, self.PORT))

    #receive node
    def receive_response(self):
        #TCP
        response_data = hashlib.sha256(self.search_id + b'ACCEPT').digest()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

        #timeout 1sec
        sock.settimeout(1)
        HOST = ''
        sock.bind((HOST, self.PORT))
        sock.listen(1)

        conn, address = sock.accept()
        self.ip_address = address[0]
        received_data = conn.recv(4096)
        sock.close()

        if received_data == response_data:
            print('Host Found: {}'.format(address))
        else:
            print('Host code is invalid')
            exit()

    def send_node(self):
        self.receive_search()
        self.response()

    #send node/receiving search packet
    def receive_search(self):
        #UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        HOST = ''
        sock.bind((HOST, self.PORT))
        search_data = hashlib.sha256(self.search_id + b'FIND').digest()
        received_data = ''
        while not received_data == search_data:
            received_data, address = sock.recvfrom(4096)
        self.ip_address = address[0]
        sock.close()

        print('Host found: {}'.format(address))

    #send node/response of search packet
    def response(self):
        #TCP
        response_data = hashlib.sha256(self.search_id + b'ACCEPT').digest()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        sock.connect((self.ip_address, self.PORT))
        sock.send(response_data)
        sock.close()


class ExchangeKey(object):
    def __init__(self, diffie_key, ip_address, PORT):
        self.diffie_key = diffie_key
        self.ip_address = ip_address
        self.PORT = PORT
        self.diffie = DiffieHellman3.DiffieHellman()
        self.gen_publickey()
        self.encrypt_publickey()

    def encrypt_publickey(self):
        padding_len, encrypted_pubkey = \
                Cipher.encrypt(self.diffie_key, str(self.pubkey).encode())
        b64_encrypted_pubkey = base64.b64encode(encrypted_pubkey)
        self.send_data = json.dumps((padding_len,
                b64_encrypted_pubkey.decode())).encode()

    def decrypt_publickey(self):
        opposit_padding_len, b64_encrypted_opposit_pubkey = \
                json.loads(self.received_data)
        encrypted_opposit_pubkey = \
                base64.b64decode(b64_encrypted_opposit_pubkey.encode())
        self.opposit_pubkey = int(Cipher.decrypt(self.diffie_key,
                opposit_padding_len, encrypted_opposit_pubkey))

    def gen_publickey(self):
        self.pubkey = self.diffie.publicKey

    def gen_key(self):
        self.diffie.genKey(self.opposit_pubkey)
        self.key = self.diffie.getKey()

    def send(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        sock.connect((self.ip_address, self.PORT))
        sock.send(self.send_data)
        sock.close()

    def receive(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

        HOST = ''
        sock.bind((HOST, self.PORT))
        sock.listen(1)

        conn, address = sock.accept()
        self.received_data = ''
        while True:
            recv_data = conn.recv(12288).decode()
            if recv_data == '':
                break
            self.received_data += recv_data

    def send_node(self):
        time.sleep(0.5)
        self.send()
        self.receive()
        self.decrypt_publickey()
        self.gen_key()

    def receive_node(self):
        self.receive()
        time.sleep(0.5)
        self.send()
        self.decrypt_publickey()
        self.gen_key()


class Transfer(object):
    def __init__(self, filename=None):
        self.filename = filename

    def get_tmpfilename(self):
        self.tmpfilename = hashlib.sha1(
            self.search_id).hexdigest()[:10]

    def get_str_padding(self, padding_len):
        str_padding_len = str(padding_len)
        if len(str_padding_len) == 1:
            str_padding_len = '0' + str_padding_len
        return str_padding_len

    def get_padding(self, str_padding_len):
        if str_padding_len[0] == '0':
            padding_len = int(str_padding_len[1])
        else:
            padding_len = int(str_padding_len)
        return padding_len

    def send(self):
        global finished_transfer
        global allow_ip_address

        print('Please enter the RandomKey on the sending machine.')
        self.randomkey = getpass.getpass('RandomKey:')
        if not len(self.randomkey) == 8:
            print('RandomKey must be 8characters')
            exit()
        psk = getpass.getpass('Pre Shared Key(Optional):')

        #generate diffiekey/search_id
        keygenerator = GenerateKey(self.randomkey, psk)
        diffie_key = keygenerator.get_key()
        self.search_id = keygenerator.get_search_id()

        #search client
        PORT = 8095
        search = SearchHost(PORT, self.search_id)
        search.send_node()
        allow_ip_address = search.ip_address

        #diffie-hellman key-exchange
        print('Key exchanging...')
        keyexchanger = ExchangeKey(diffie_key, search.ip_address, PORT)
        keyexchanger.send_node()
        encryptkey = keyexchanger.key

        #make data
        print('Encrypting...')
        filedata = open(self.filename, 'rb').read()
        self.get_tmpfilename()
        padding_len, encrypted_data = Cipher.encrypt(encryptkey, filedata)
        str_padding_len = self.get_str_padding(padding_len)
        self.encrypted_transdata = str_padding_len.encode() + encrypted_data

        #make metadata
        hash_data = hashlib.sha512(filedata).hexdigest()
        metadata = json.dumps(
            {'filename': self.filename, 'hash': hash_data}).encode()
        meta_padding_len, encrypted_metadata = \
            Cipher.encrypt(encryptkey, metadata)
        str_meta_padding_len = self.get_str_padding(meta_padding_len)
        self.encrypted_transmetadata = \
            str_meta_padding_len.encode() + encrypted_metadata

        #run server
        socketserver.TCPServer.allow_reuse_address = True
        httpd = socketserver.TCPServer(("", PORT), TransHandler)

        finished_transfer = False
        while not finished_transfer:
            httpd.handle_request()
        print('Sending complete')

    def receive(self):
        self.randomkey = RandomKey().get()
        print('RandomKey:{}'.format(self.randomkey))
        psk = getpass.getpass('Pre Shared Key(Optional):')

        keygenerator = GenerateKey(self.randomkey, psk)
        diffie_key = keygenerator.get_key()
        self.search_id = keygenerator.get_search_id()

        self.get_tmpfilename()

        #search host
        PORT = 8095
        search = SearchHost(PORT, self.search_id)
        search.receive_node()
        ip_addr = search.ip_address

        #diffie-hellman key exchange
        print('Key exchanging...')
        keyexchanger = ExchangeKey(diffie_key, ip_addr, PORT)
        keyexchanger.receive_node()
        encryptkey = keyexchanger.key

        #read metadata
        base_uri = 'http://{}:{}/'.format(ip_addr, PORT)
        metadata_uri = base_uri + self.tmpfilename + '_data'
        not_connected = True
        #wait for ready
        while not_connected:
            time.sleep(1)
            try:
                encrypted_transmetadata = urllib.request.urlopen(metadata_uri).read()
            except urllib.error.URLError as e:
                pass
            else:
                not_connected = False

        encrypted_metadata = encrypted_transmetadata[2:]
        str_meta_padding_len = encrypted_transmetadata[:2]
        meta_padding_len = self.get_padding(str_meta_padding_len)
        metadata = Cipher.decrypt(
            encryptkey, meta_padding_len, encrypted_metadata).decode()

        self.filename = json.loads(metadata)['filename']
        hash_data = json.loads(metadata)['hash']

        #read data
        print('Receiving...')
        data_uri = base_uri + self.tmpfilename
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

        print('Receiving complete: {}({}Bytes)'.format(
            self.filename, len(data)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-s', '--send', metavar='FILENAME')
    args = parser.parse_args()
    if args.send:
        transfer = Transfer(args.send)
        transfer.send()
    else:
        transfer = Transfer()
        transfer.receive()
