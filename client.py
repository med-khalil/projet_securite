import os
import datetime
import json
import socket
import threading
import argparse

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes


class Client:
    def __init__(self, server, port, userId):
        self.server = server
        self.port = port
        self.userId = userId

    def create_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server, self.port))
        except Exception as e:
            print('Error !')

        self.s.send(self.userId.encode())
        print('+ Connected established')
        print('+ key Exchange')

        self.init_key_pair()
        self.send_public_keys()
        global private_key
        private_key = self.handle_secret()

        print('messages exchange in progress ...')

        message_handler = threading.Thread(target=self.handle_msg, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.input_handler, args=())
        input_handler.start()

    def handle_msg(self):
        while True:
            message = self.s.recv(1024).decode()
            if message:
                key = private_key
                decrypt_message = json.loads(message)
                iv = b64decode(decrypt_message['iv'])
                cipherText = b64decode(decrypt_message['ciphertext'])
                cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                msg = cipher.decrypt(cipherText)
                current_time = datetime.datetime.now()
                print(current_time.strftime(
                    '%d-%m-%Y %H:%M:%S ')+msg.decode())
            else:
                print('[!]  Connection to the server Lost')
                self.s.shutdown(socket.SHUT_RDWR)
                os._exit(0)

    def input_handler(self):
        while True:
            message = input()
            if message == "EXIT":
                break
            else:
                key = private_key
                cipher = AES.new(key, AES.MODE_CFB)
                message_to_encrypt = "User Id : " + self.userId + \
                    " || message content : " + message
                msgBytes = message_to_encrypt.encode()
                encrypted_message = cipher.encrypt(msgBytes)
                iv = b64encode(cipher.iv).decode('utf-8')
                message = b64encode(encrypted_message).decode('utf-8')
                result = json.dumps({'iv': iv, 'ciphertext': message})
                self.s.send(result.encode())

        self.s.shutdown(socket.SHUT_RDWR)
        os._exit(0)

    def handle_secret(self):
        secret_key = self.s.recv(1024)
        private_key = RSA.importKey(open('client_private_key.pem', 'r').read())
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(secret_key)

    def send_public_keys(self):
        try:
            print('+ Getting public key from the server')
            server_public_key = self.s.recv(1024).decode()
            server_public_key = RSA.importKey(server_public_key)

            print('+ Sending public key to server')
            public_pem_key = RSA.importKey(
                open('client_public_key.pem', 'r').read())
            self.s.send(public_pem_key.exportKey())
            print('+ Exchange completed!')

        except Exception as e:
            print(e)

    def init_key_pair(self):
        try:
            private_key = RSA.generate(2048)
            public_key = private_key.publickey()
            private_pem = private_key.exportKey().decode()
            public_pem = public_key.exportKey().decode()
            with open('client_private_key.pem', 'w') as priv:
                priv.write(private_pem)
            with open('client_public_key.pem', 'w') as pub:
                pub.write(public_pem)

        except Exception as e:
            print(e)


if __name__ == "__main__":
    arg_parse = argparse.ArgumentParser()
    arg_parse.add_argument('-p', '--port', required=True,
                           type=int, help="port the server listening on")
    arg_parse.add_argument('-s', '--server', required=True,
                           help="server ip to connect")
    arg_parse.add_argument(
        '-u', '--username', required=True, help="username of the user")
    args = arg_parse.parse_args()
    client = Client(args.server, args.port, args.username)
    client.create_connection()
