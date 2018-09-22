#!/usr/bin/env python3

import sys
import socket
import selectors
import types
import os
from Crypto.Cipher import AES

sel = selectors.DefaultSelector()

def perform_decryption(ciphertext_with_tag_nonce):
    key = b'Sixteen byte key'
    print("Decryption Function")
    print(len(ciphertext_with_tag_nonce))
    nonce = ciphertext_with_tag_nonce[-16:]
    tag = ciphertext_with_tag_nonce[-32:-16]
    ciphertext = ciphertext_with_tag_nonce[:len(ciphertext_with_tag_nonce)-32]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    # print("Post Decrypt : Ciphertext, nonce, tag", ciphertext, nonce, tag)
    print("Message length", len(ciphertext), len(tag), len(nonce))
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("The message is authentic:", plaintext)
    except ValueError:
        print("Key incorrect or message corrupted")

def perform_encryption(file_messages):

    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(file_messages.encode())
    # print("Message length", len(ciphertext), len(tag), len(nonce))
    print("After encrypt : Ciphertext, nonce, tag", ciphertext, nonce, tag)
    #1536, 16, 16
    ciphertext_with_tag_nonce = ciphertext+tag+nonce

    return ciphertext, tag, nonce

def create_Message(filename="bigfile_server.txt"):
    #Should recieve a filename
    file_messages, file_size = read_file_create_list()
    ciphertext, tag , nonce = perform_encryption(file_messages)
    print("Ciphertext, nonce, tag", ciphertext, nonce, tag)
    return ciphertext + tag + nonce


def read_file_create_list(filename="bigfile_server.txt"):
    with open(filename,"r+") as f:
        file_messages = str(f.read())
        file_size = sum(len(item) for item in list(file_messages))

    return file_messages, file_size

def accept_wrapper(sock):
    conn, addr = sock.accept()  # Should be ready to read
    print('accepted connection from', addr)
    conn.setblocking(False)
    full_message = create_Message()

    message_size = len(full_message)
    print(message_size)
    data = types.SimpleNamespace(addr=addr, recv_data_client = b'',inb=b'', outb=b'', messages=full_message, len_messages=message_size)
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)


def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    recieved_data = []
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(64000)  # Should be ready to read
        if recv_data:
            data.outb += recv_data
        else:
            print('closing connection to', data.addr)
            perform_decryption(data.recv_data_client)
            sel.unregister(sock)
            sock.close()
    if mask & selectors.EVENT_WRITE:
        if not data.outb and data.messages:
            data.outb = data.messages
            # print("First time setting of messages", data.outb)
        if data.outb:
            print("Here is an output function for you")
            sock.sendall(data.outb)
            data.recv_data_client+=data.outb
            print("Total length of data sent", len(data.outb))
            sock.shutdown(socket.SHUT_WR)


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
