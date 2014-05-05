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
import os.path
import logging
from multiprocessing import Process, Queue, Value
import math

SALT = '''aD'T&,\L}u]Ghju[vGTuWxM{1,W]86a,Qb3OO/0eS$1}7cDmA[o61?#?sLF^\B|&}~vs
{skgAhkb,=)qY9*xJQ.I9z6JEUbKkP1&$:j%5mHAv=Cp6Hw]bXN8NgE5HL1sRl%%,WS!"|;Z&D{=KO
4\`z+/!0%&1@awanH"Z4c-hhd1"qrVr!~a:v}Et*kO7;@B@EipP.+RuDb]z$#QwRn25Ft_>+fG},*$
$NEpR|)muq?e6q&>j~,1Gj{IdecLtDzSSyK2z8wWH'Q]<&8P~'QIlX|~PY*]=sQakDO55}lmFehH'''


class RandomKey(object):
    def __init__(self):
        char_map = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz'
        key_length = 8
        self.randomkey = ''.join(
            [random.choice(char_map) for i in range(key_length)])

    def get(self):
        return self.randomkey


class GenerateKey(object):
    def __init__(self, randomkey, psk):
        hash_times = 10000
        seed = randomkey + psk + SALT
        self.hash_result = str(seed).encode()
        for i in range(hash_times):
            self.hash_result += (psk + SALT).encode()
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
        if self.client_address[0] == transfer.allow_ip_address:
            self.send_response(200, 'OK')
            self.send_header('Content-type', 'html')
            self.end_headers()
            req_filename, number = self.path[1:].split('-')
            if req_filename == transfer.tmpfilename:
                number = int(number)
                already_transfer = transfer.seg_size_mib * number
                whole_transfer = transfer.seg_size_mib * transfer.seg_numbers
                logging.info('Sending...{}MiB/{}MiB'.format(
                    already_transfer, whole_transfer))
                transdata = transfer.data_q.get()
                self.wfile.write(transdata)
                #count finished seg numbers
                transfer.finished_trans_num.value += 1
            elif req_filename == transfer.tmpfilename + '_data':
                if not number:
                    metadata = transfer.global_metadata
                else:
                    metadata = transfer.metadata_q.get()
                self.wfile.write(metadata)

    def do_HEAD(self):
        pass

    #be quiet!
#    def log_message(self, format, *args):
#        pass


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
            logging.info('Host Found: {}'.format(address))
        else:
            logging.error('Host code is invalid')
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

        logging.info('Host found: {}'.format(address))

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
        padding_len, encrypted_pubkey = Cipher.encrypt(
            self.diffie_key, str(self.pubkey).encode())
        b64_encrypted_pubkey = base64.b64encode(encrypted_pubkey)
        self.send_data = json.dumps(
            (padding_len, b64_encrypted_pubkey.decode())).encode()

    def decrypt_publickey(self):
        opposit_padding_len, b64_encrypted_opposit_pubkey = json.loads(
            self.received_data)
        encrypted_opposit_pubkey = base64.b64decode(
            b64_encrypted_opposit_pubkey.encode())
        self.opposit_pubkey = int(Cipher.decrypt(
            self.diffie_key, opposit_padding_len, encrypted_opposit_pubkey))

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
    def __init__(self, port):
        if not port:
            self.PORT = 8095
        else:
            self.PORT = int(port)

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


    #metadata maker
    def make_metadata(self, metadata):
        metadata = json.dumps(metadata).encode()
        meta_padding_len, encrypted_metadata = \
            Cipher.encrypt(self.encryptkey, metadata)
        str_meta_padding_len = self.get_str_padding(meta_padding_len)
        encrypted_transmetadata = \
            str_meta_padding_len.encode() + encrypted_metadata
        return encrypted_transmetadata

    
    def send(self, filename, compress_type):
        self.filename = filename
        self.compress_type = compress_type

        print('Please enter the RandomKey on the sending machine.')
        try:
            self.randomkey = getpass.getpass('RandomKey:')
            if not len(self.randomkey) == 8:
                logging.error('RandomKey must be 8characters')
                exit()
            psk = getpass.getpass('Pre Shared Key(Optional):')
        except KeyboardInterrupt:
            print()
            exit()

        #generate diffiekey/search_id/tmpfilename
        keygenerator = GenerateKey(self.randomkey, psk)
        diffie_key = keygenerator.get_key()
        self.search_id = keygenerator.get_search_id()
        self.get_tmpfilename()

        #search client
        search = SearchHost(self.PORT, self.search_id)
        search.send_node()
        self.allow_ip_address = search.ip_address

        #diffie-hellman key-exchange
        logging.info('Key exchanging...')
        keyexchanger = ExchangeKey(diffie_key, search.ip_address, self.PORT)
        keyexchanger.send_node()
        self.encryptkey = keyexchanger.key

        #prepare data
        self.file_path = os.path.abspath(self.filename)
        basename = os.path.basename(self.filename)
        self.file_size = os.path.getsize(self.filename)
        self.fileobj = open(self.file_path, 'rb')
        hash_data = hashlib.sha512(self.fileobj.read()).hexdigest()
        self.fileobj.close()

        self.seg_numbers = math.ceil(self.file_size / self.seg_size)

        #make metadata
        metadata = {
            'filename': basename,
            'hash': hash_data,
            'seg_numbers': self.seg_numbers,
            'compress_type': self.compress_type,
            'seg_size': self.seg_size,
            'seg_size_mib': self.seg_size_mib,
        }
        self.global_metadata = self.make_metadata(metadata)

        #launch segprocess
        self.data_q = Queue()
        self.metadata_q = Queue()
        seg_p = Process(target=segprocess, args=(
            self.file_path, self.seg_size, self.seg_numbers, self.max_seg, 
            self.compress_type, self.data_q, self.metadata_q, self.encryptkey))
        seg_p.start()

        #launch server
        self.finished_trans_num = Value('L', 0)
        server_p = Process(target=server, 
                           args=(self.PORT, self.finished_trans_num, self.seg_numbers))
        server_p.start()
        server_p.join()

        logging.info('Sending complete')

    def receive(self):
        #check download dir
        download_dir = 'DownloadFiles'
        try:
            os.mkdir(download_dir)
        except FileExistsError:
            pass
        self.randomkey = RandomKey().get()
        try:
            print('RandomKey:{}'.format(self.randomkey))
            psk = getpass.getpass('Pre Shared Key(Optional):')
        except KeyboardInterrupt:
            print()
            exit()

        keygenerator = GenerateKey(self.randomkey, psk)
        diffie_key = keygenerator.get_key()
        self.search_id = keygenerator.get_search_id()

        self.get_tmpfilename()

        #search host
        search = SearchHost(self.PORT, self.search_id)
        search.receive_node()
        ip_addr = search.ip_address

        #diffie-hellman key exchange
        logging.info('Key exchanging...')
        keyexchanger = ExchangeKey(diffie_key, ip_addr, self.PORT)
        keyexchanger.receive_node()
        encryptkey = keyexchanger.key

        base_uri = 'http://{}:{}/'.format(ip_addr, self.PORT)
        #read metadata
        def get_metadata(num):
            metadata_uri = base_uri + self.tmpfilename + '_data-'+num
            encrypted_transmetadata = urllib.request.urlopen(
                metadata_uri).read()
            encrypted_metadata = encrypted_transmetadata[2:]
            str_meta_padding_len = encrypted_transmetadata[:2]
            meta_padding_len = self.get_padding(str_meta_padding_len)
            metadata = Cipher.decrypt(
                encryptkey, meta_padding_len, encrypted_metadata).decode()
            return metadata

        not_connected = True
        #wait for ready
        while not_connected:
            time.sleep(0.5)
            try:
                global_metadata_json = get_metadata('')
            except urllib.error.URLError as e:
                if e.args[0].errno != 111:
                    logging.error(e)
            else:
                not_connected = False
        
        global_metadata = json.loads(global_metadata_json)
        self.filename = global_metadata['filename']
        hash_data = global_metadata['hash']
        seg_numbers = global_metadata['seg_numbers']
        compress_type = global_metadata['compress_type']
        self.seg_size = global_metadata['seg_size']
        self.seg_size_mib = global_metadata['seg_size_mib']


        #write with only filename(ex. /boot/hoge->hoge)
        self.filename = os.path.basename(self.filename)
        #if already exists
        self.write_filename = self.filename
        file_ver = 1
        while os.path.exists(os.path.join(download_dir, self.write_filename)):
            logging.warning('"{}" already exists'.format(self.write_filename))
            #for multiple ext
            ext = None
            tail = ''
            rootname = self.filename
            while ext != '':
                rootname, ext = os.path.splitext(rootname)
                tail = ext + tail
            self.write_filename = '{}-{}{}'.format(rootname, file_ver, tail)
            file_ver += 1

        write_path = os.path.join(download_dir,self.write_filename)
        logging.info('Save as {}'.format(write_path))

        #receive data
        def get_data():
            with open(write_path, 'wb') as f:
                for seg_num in range(seg_numbers):
                    already_transfer = self.seg_size_mib * seg_num
                    whole_transfer = self.seg_size_mib * seg_numbers
                    logging.info('Receiving... {}MiB/{}MiB'.format(
                        already_transfer, whole_transfer))
                    data_uri = base_uri + self.tmpfilename + '-' + str(seg_num)
                    encrypted_transdata = urllib.request.urlopen(data_uri).read()
                    encrypted_data = encrypted_transdata[2:]
                    str_padding_len = encrypted_transdata[:2]
                    padding_len = self.get_padding(str_padding_len)

                    compressed_data = Cipher.decrypt(encryptkey, padding_len, encrypted_data)
                
                    #decompress
                    #not compressed
                    if compress_type == 'none':
                        data = compressed_data
                    elif compress_type == 'zlib':
                        import zlib
                        data = zlib.decompress(compressed_data)
                    elif compress_type == 'bz2':
                        import bz2
                        data = bz2.decompress(compressed_data)

                    #TODO
                    #hash validation check with metadata
                    
                    #write
                    f.write(data)

        get_data()

        logging.info('Receiving complete: {}({}Bytes)'.format(
            self.filename, os.path.getsize(write_path)))


#process for each transfer segment
def segprocess(file_path, seg_size, seg_numbers, max_seg, compress_type,
               data_q, metadata_q, encryptkey):
    Random.atfork()
    #read data
    fileobj = open(file_path, 'rb')

    for seg_num in range(seg_numbers):
        #wait for sending
        while data_q.qsize() >= max_seg:
            time.sleep(0.1)

        segdata = fileobj.read(seg_size)

        #compress
        if compress_type == 'none':
            compressed_data = segdata
        elif compress_type == 'zlib':
            import zlib
            compressed_data = zlib.compress(segdata)
        elif compress_type == 'bz2':
            import bz2
            compressed_data = bz2.compress(segdata)

        #encrypt
        padding_len, encrypted_data = Cipher.encrypt(encryptkey, compressed_data)
        str_padding_len = transfer.get_str_padding(padding_len)
        encrypted_transdata = str_padding_len.encode() + encrypted_data
        
        #make metadata
        hash_data = hashlib.sha512(segdata).hexdigest()
        metadata = {
            'hash': hash_data,}
        transmetadata = transfer.make_metadata(metadata)

        #put in queue
        metadata_q.put(transmetadata)
        data_q.put(encrypted_transdata)

def server(PORT, finished_trans_num, seg_numbers):
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("", PORT), TransHandler)

    while not finished_trans_num.value >= seg_numbers:
        httpd.handle_request()

if __name__ == '__main__':
    def split_type(s):
        default = 'zlib'
        if ":" in s:
            return tuple(s.split(":", 1))
        else:
            return s, default

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-s', '--send', metavar='FILENAME[:COMPRESS-TYPE]',
                        help='Compress:zlib(default),bz2,none', type=split_type)
    parser.add_argument('-p', '--port', type=int, metavar='PORT')
    args = parser.parse_args()

    log_fmt = '%(asctime)s- %(levelname)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=log_fmt)

    transfer = Transfer(args.port)
    transfer.max_seg = 5 #500MiB
    
    if args.send:
        filename, compress = args.send
        if compress in ['zlib','bz2','none']:
            transfer.seg_size = 104857600 #100MiB
            transfer.seg_size_mib = 100
            transfer.send(filename, compress)
        else:
            logging.error('Compress type must be zlib, bz2 or none')
    else:
        transfer.receive()
