import socket
import threading
import argparse
import os
import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


class Server:
    def __init__(self, port):
        self.host = '127.0.0.1'
        self.port = port

    def start_server(self):
        self.generate_keys()
        secret_key = get_random_bytes(16)

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.clients = []

        self.s.bind((self.host, self.port))
        self.s.listen(100)

        print('+ Running on host: '+str(self.host))
        print('+ Running on port: '+str(self.port))

        self.UserId_lookup = {}

        while True:
            c, addr = self.s.accept()
            UserId = c.recv(1024).decode()
            print('+ New connection. UserId: '+str(UserId))
            self.broadcast(
                ' New person joined the room. UserId: '+UserId)
            self.UserId_lookup[c] = UserId
            self.clients.append(c)
            client_pub_key = self.send_pub_key(c)
            encrypted_secret = self.encrypt_secret(client_pub_key, secret_key)
            self.send_secret(c, encrypted_secret)
            threading.Thread(target=self.handle_client,
                             args=(c, addr,)).start()

    def broadcast(self, msg):
        for connection in self.clients:
            print('+ Broadcast message: '+msg)

    def generate_keys(self):
        try:
            private_key = RSA.generate(2048)
            public_key = private_key.publickey()
            private_key_pem = private_key.exportKey().decode()
            public_key_pem = public_key.exportKey().decode()
            with open('server_private_key.pem', 'w') as priv:
                priv.write(private_key_pem)
            with open('server_public_key.pem', 'w') as pub:
                pub.write(public_key_pem)
            return public_key

        except Exception as e:
            print(e)

    def encrypt_secret(self, client_pub_key, secret_key):
        try:
            cpKey = RSA.importKey(client_pub_key)
            cipher = PKCS1_OAEP.new(cpKey)
            encrypted_secret = cipher.encrypt(secret_key)
            return encrypted_secret

        except Exception as e:
            print(e)

    def send_secret(self, c, secret_key):
        try:
            c.send(secret_key)
            print('+ Secret key had been sent to the client')

        except Exception as e:
            print(e)

    def send_pub_key(self, c):
        try:
            public_key = RSA.importKey(
                open('server_public_key.pem', 'r').read())
            c.send(public_key.exportKey())
            client_pub_key = c.recv(1024)
            print('+ Client public key had been received')
            return client_pub_key

        except Exception as e:
            print(e)

    def handle_client(self, c, addr):

        while True:
            try:
                msg = c.recv(1024)
            except:
                c.shutdown(socket.SHUT_RDWR)
                self.clients.remove(c)
                self.broadcast(str(self.UserId_lookup[c])+' has left.')
                break

            if msg.decode() != '':
                current_time = datetime.datetime.now()
                print(current_time.strftime(
                    '%d-%m-%Y %H:%M:%S')+' Mesage exchanged')
                for connection in self.clients:
                    if connection != c:
                        connection.send(msg)
            else:
                print('+ ' + self.UserId_lookup[c] + ' left the server.')
                for conn in self.clients:
                    if conn == c:
                        self.clients.remove(c)
                break


def terminate(Server):
    while True:
        command = input('')
        if (command == 'TERMINATE'):
            for conn in Server.clients:
                conn.shutdown(socket.SHUT_RDWR)
            print('+ All connections had been terminated')
        break
    print('+ Server shut down')
    os._exit(0)


if __name__ == "__main__":
    arg_parse = argparse.ArgumentParser()
    arg_parse.add_argument("-p", "--port", type=int,
                           required=True, help="port to run the server")
    args = arg_parse.parse_args()

    server = Server(args.port)
    terminate = threading.Thread(target=terminate, args=(server,))
    terminate.start()
    server.start_server()
