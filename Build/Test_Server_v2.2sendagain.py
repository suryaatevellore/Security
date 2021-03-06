#!/usr/bin/env python3

#What this program does right now
#Implements GCM
#Implements bi directional traffic

#What we need to do
#-> Combine files
#-> Implement argparse



import sys
import socket
import selectors
import types
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

sel = selectors.DefaultSelector()

def perform_decryption(ciphertext_added):
    try:
        password = b'Sixteen byte key'
        salt = ciphertext_added[:8]
        key = PBKDF2(password, salt)
        tag = ciphertext_added[8:24]
        nonce = ciphertext_added[24:40]
        ciphertext=ciphertext_added[40:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        print("Message length", len(ciphertext), len(tag), len(nonce))
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print("The message is authentic:", plaintext)

    except ValueError:
        print("Key incorrect or message corrupted")

    except KeyError:
        print("Key incorrect or message corrupted")

def perform_encryption(file_messages):
    salt=os.urandom(8)
    password = b'Sixteen byte key'
    key = PBKDF2(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(file_messages.encode())
    # print("Message length", len(ciphertext), len(tag), len(nonce))
    # print("After encrypt : Ciphertext, nonce, tag", ciphertext, nonce, tag)
    return ciphertext, tag, nonce, salt


def accept_wrapper(sock):
    conn, addr = sock.accept()  # Should be ready to read
    print('accepted connection from', addr)
    conn.setblocking(False)
    full_message = create_Message("bigfile_server.txt")
    print("This is the full message to read", full_message)
    data = types.SimpleNamespace(addr=addr, recv_data_client = b'',inb=b'', outb=b'', messages='', written_once=1, monitor_server=1)
    data.messages = full_message
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)


def create_Message(filename):
    #Should recieve a filename
    file_messages, file_size = read_file_create_list(filename)
    ciphertext, tag , nonce, salt = perform_encryption(file_messages)
    return salt+tag+nonce+ciphertext


def read_file_create_list(filename):
    with open(filename,"r+") as f:
        file_messages = str(f.read())
        file_size = sum(len(item) for item in list(file_messages))

    return file_messages, file_size


def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(64000)  # Should be ready to read
        if recv_data:
            data.inb += recv_data
        else:
            print('closing connection to', data.addr)
            print("Here is the inbound data", data.inb)
            perform_decryption(data.inb)
            sel.unregister(sock)
            sock.close()

    if mask & selectors.EVENT_WRITE:
        if not data.outb and data.messages and data.written_once==1:
            print("This is the first time set. Should not be set again")
            data.outb = data.messages
            print("This is the current value of data.messages", data.outb)
        if data.outb:
            print(data.outb)
            print("Total length of data before sending", len(data.outb))
            # print("Data before sending", data.outb)
            sent = sock.send(data.outb)  # Should be ready to write
            data.written_once=2
            data.outb = data.outb[sent:]
            sock.shutdown(socket.SHUT_WR)
            print(f"Length of data.outb after first {sent} bytes is {len(data.outb)}")



if len(sys.argv) != 3:
    print('usage:', sys.argv[0], '<host> <port>')
    sys.exit(1)

host, port = sys.argv[1], int(sys.argv[2])
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.bind((host, port))
lsock.listen()
print('listening on', (host, port))
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)

try:
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                service_connection(key, mask)
except KeyboardInterrupt:
    print('caught keyboard interrupt, exiting')
finally:
    sel.close()
