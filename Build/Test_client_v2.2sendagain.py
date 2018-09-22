#!/usr/bin/env python3

import sys
import socket
import selectors
import types
import os
import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

sel = selectors.DefaultSelector()
file_size = 0
#Open the file and read it into the list file_messages
file_messages = []

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

def read_file_create_list(filename="smallfile_client.txt"):
    with open(filename,"r+") as f:
        file_messages = str(f.read())
        file_size = sum(len(item) for item in list(file_messages))

    return file_messages, file_size

def create_Message(filename="smallfile_client.txt"):
    #Should recieve a filename
    file_messages, file_size = read_file_create_list()
    ciphertext, tag , nonce, salt = perform_encryption(file_messages)
    # print("Ciphertext, nonce, tag, salt", ciphertext, nonce, tag, salt)

    return salt+tag+nonce+ciphertext


def start_connections(host, port, num_conns, filename="smallfile_client.txt"):
    #this should recieve the name of a file via argparse
    full_message = create_Message()
    message_size = len(full_message)
    # print("Message Size", message_size)
    server_addr = (host, port)
    for i in range(0, num_conns):
        connid = i + 1
        print('starting connection', connid, 'to', server_addr)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.connect_ex(server_addr)
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        data = types.SimpleNamespace(connid=connid,
                                     msg_total=message_size,
                                     recv_total=0,
                                     messages=full_message,
                                     outb=b'', written_once=1)
        sel.register(sock, events, data=data)

def service_connection(key, mask):
    print("Entered here")
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(64000)  # Should be ready to read
        if recv_data:
            # print('received', repr(recv_data), 'from connection', data.connid)
            data.recv_total += len(recv_data)
            print("Total data recieved",data.recv_total,data.msg_total,"\n")

        if not recv_data or data.recv_total==data.msg_total:
            print("Total sent and recieved", data.recv_total, data.msg_total)
            print('closing connection', data.connid)
            sel.unregister(sock)
            sock.close()

    if mask & selectors.EVENT_WRITE:
        if not data.outb and data.messages and data.written_once==1:
            print("This is the first time set. Should not be set again")
            data.outb = data.messages
            data.size_outb = len(data.messages)

        if data.outb:
            print("Total length of data before sending", len(data.outb))
            # print("Data before sending", data.outb)
            sent = sock.send(data.outb)  # Should be ready to write
            data.written_once=2
            data.outb = data.outb[sent:]
            print(f"Length of data.outb after first {sent} bytes is {len(data.outb)}")


if len(sys.argv) != 4:
    print('usage:', sys.argv[0], '<host> <port> <num_connections>')
    sys.exit(1)

host, port, num_conns = sys.argv[1:4]
start_connections(host, int(port), int(num_conns))

try:
    while True:
        events = sel.select(timeout=1)
        if events:
            for key, mask in events:
                service_connection(key, mask)
        # Check for a socket being monitored to continue.
        if not sel.get_map():
            break
except KeyboardInterrupt:
    print('caught keyboard interrupt, exiting')
finally:
    sel.close()
