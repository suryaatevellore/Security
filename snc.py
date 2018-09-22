#!/usr/bin/env python3


import sys
import socket
import selectors
import types
import os
import argparse
import sys
import stat
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

sel = selectors.DefaultSelector()

def perform_decryption(ciphertext_added, password):
    """
        This method takes in a ciphertext and a password adjoined with a nonce and tag header and returns a plaintext value.
    """
    try:
        salt = ciphertext_added[:8]
        key = PBKDF2(password, salt)
        tag = ciphertext_added[8:24]
        nonce = ciphertext_added[24:40]
        ciphertext=ciphertext_added[40:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        write_file(plaintext)

    except ValueError:
        print("Key incorrect or message corrupted or no no input data")

    except KeyError:
        print("Key incorrect or message corrupted or no input data")

def perform_encryption(file_messages, password):
    """
        Function for generatng a random salt for encrypting usin AES in GCM mode
    """
    salt=os.urandom(8)
    key = PBKDF2(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(file_messages)
    return salt, tag, nonce, ciphertext


def accept_wrapper(sock, password):
    """
        One of the functions of the server loop which acts a constructor for creating client sockets on the server side. Using SimpleNameSpace class, it generates initial variables specific to the socket
    """
    conn, addr = sock.accept()  # Should be ready to read
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, recv_data_client = b'',inb=b'', outb=b'', messages='', written_once=1, message_size=0)
    data.messages= create_Message(password)
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

def create_Message(password):
    """
        Fcunction for generating a header consisting of salt, tag and nonce along with the ciphertext
    """
    file_messages = read_file()
    if file_messages:
        salt, tag, nonce, ciphertext = perform_encryption(file_messages, password)
        return salt+tag+nonce+ciphertext
    else:
        file_messages = []

def read_file():
    """
        Using os.stat library, this function determines if there is a file that been redirected through sys.stdin
    """
    mode = os.fstat(0).st_mode
    if stat.S_ISREG(mode):
        server_bytes = sys.stdin.read().encode('utf-8')
        return server_bytes
    else:
        return ''

def write_file(data):
    """
        Additional function for writing data to sys.stdout
    """
    sys.stdout.write(data.decode('utf-8'))

def start_connections(host, port, password):
    """
        Function that initialises te variables for the client socket
    """
    server_addr = (host, port)
    num_conns = 1
    for i in range(0, num_conns):
        connid = i + 1
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.connect_ex(server_addr)

        full_message = create_Message(password)
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        data_client = types.SimpleNamespace(connid=connid,
                                     recv_total=0,
                                     messages=full_message,
                                     outb=b'', written_once=1,
                                     data_client_rcvd = b'')
        sel.register(sock, events, data=data_client)

def service_connection_client(key, mask, password):
    """
        Function which uses Selectoes Class to multiplex between receive and sends without blocking IO for the client
    """
    try:
        sock = key.fileobj
        data_client = key.data
        if mask & selectors.EVENT_READ:
            recv_data_client = sock.recv(64000)  # Should be ready to read
            if recv_data_client:
                data_client.data_client_rcvd+=recv_data_client


            else :
                perform_decryption(data_client.data_client_rcvd, password)
                sel.unregister(sock)
                sock.close()

        if mask & selectors.EVENT_WRITE:
            if not data_client.messages:
                sock.send(b"bye")

            if not data_client.outb and data_client.messages and data_client.written_once==1:
                data_client.outb = data_client.messages
                data_client.size_outb = len(data_client.messages)

            if data_client.outb:
                sent = sock.send(data_client.outb)  # Should be ready to write
                data_client.written_once=2
                data_client.outb = data_client.outb[sent:]

    except socket.error as e:
        pass

    except OSError as e:
        pass


def service_connection(key, mask, password):
    """
        Function which uses Selectoes Class to multiplex between receive and sends without blocking IO
    """
    try:
        sock = key.fileobj
        data = key.data
        if mask & selectors.EVENT_READ:
            recv_data = sock.recv(64000)  # Should be ready to read

            if recv_data:
                data.inb += recv_data

            else:
                perform_decryption(data.inb, password)
                sel.unregister(sock)
                sock.close()
                sys.exit(0)

        if mask & selectors.EVENT_WRITE:
            if not data.messages:
                sock.shutdown(socket.SHUT_WR)


            if not data.outb and data.messages and data.written_once==1:
                data.outb = data.messages
            if data.outb:
                sent = sock.send(data.outb)  # Should be ready to write
                data.written_once=2
                data.outb = data.outb[sent:]
                sock.shutdown(socket.SHUT_WR)

    except socket.error as e:
        pass

    except OSError as e:
        pass


def Server(host, port, password):
    """
        main Server loop
    """
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind((host, port))
    lsock.listen()
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)

    try:
        while True:
            events = sel.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    accept_wrapper(key.fileobj,password)
                else:
                    service_connection(key,mask,password)
    except KeyboardInterrupt:
        print('caught keyboard interrupt, exiting')
    finally:
        sel.close()

def Client(host, port, password):
    """
        Main Client loop
    """
    start_connections(host, int(port), password)
    try:
        while True:
            events = sel.select(timeout=1)
            if events:
                for key, mask in events:
                    service_connection_client(key, mask, password)
            if not sel.get_map():
                break
    except KeyboardInterrupt:
        print('caught keyboard interrupt, exiting')
    finally:
        sel.close()



def main():
    """
        Argument parsing only
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--key', action="store", required=True,help="Enter the key value", dest="password", type=str)
    parser.add_argument('-l', help="Specify if the socket should be a listening socket", action="store_true", dest="listen")
    parser.add_argument("destination", nargs="?",help="Specify the Server IP Address", default='127.0.0.1')
    parser.add_argument("port", action="store", type=int, help="Specify the Server port")
    args = parser.parse_args()

    password = args.password
    listen = args.listen
    port = args.port
    server_address = args.destination


    if listen:
        Server(server_address, port, password)

    else:
        Client(server_address, port, password)


if __name__ == "__main__":
    main()
