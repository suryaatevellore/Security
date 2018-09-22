#!/usr/bin/env python3

import sys
import socket
import selectors
import types
import os
import sys
import json
from Crypto.Cipher import AES

key = b'Sixteen byte key'
sel = selectors.DefaultSelector()
file_size = 0
#Open the file and read it into the list file_messages
file_messages = []
#Calculate the total length of the file
print("File SIZE !!!!!", file_size)
print("Actual file", file_messages)

def perform_encryption():
    #This should recieve the key via argparse
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag, nonce

def read_file_create_list(filename="smallfile_client.txt"):
    with open(filename,"r+") as f:
        file_messages = f.read().encode().splitlines()
        file_size = sum(len(item) for item in file_messages)

    return file_messages, file_size

def create_Message(filename="smallfile_client.txt"):
    #Should recieve a filename
    file_messages, file_size = read_file_create_list()
    ciphertext, tag , nonce = perform_encryption(file_messages)
    complete_message = ciphertext +"#" + tag + "#" + nonce
    encoded_hand = json.dumps(complete_message)
    return encoded_hand


def start_connections(host, port, num_conns, filename="smallfile_client.txt"):
    #this should recieve the name of a file via argparse
    file_messages, file_size = read_file_create_list(filename)
    server_addr = (host, port)
    for i in range(0, num_conns):
        connid = i + 1
        print('starting connection', connid, 'to', server_addr)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.connect_ex(server_addr)
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        data = types.SimpleNamespace(connid=connid,
                                     msg_total=file_size,
                                     recv_total=0,
                                     messages=list(file_messages),
                                     outb=b'')
        sel.register(sock, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)  # Should be ready to read
        if recv_data:
            # print('received', repr(recv_data), 'from connection', data.connid)
            data.recv_total += len(recv_data)
            print("Total data recieved",data.recv_total,data.msg_total,"\n")
        if not recv_data or data.recv_total == data.msg_total:
            print('closing connection', data.connid)
            sel.unregister(sock)
            sock.close()
    if mask & selectors.EVENT_WRITE:
        if not data.outb and data.messages:
            data.outb = data.messages.pop(0)
            print("*****Popped outb******", data.outb)
        if data.outb:
            print('sending', repr(data.outb), 'to connection', data.connid,"\n'")
            sent = sock.send(data.outb)  # Should be ready to write
            data.outb = data.outb[sent:]
        # if not data.outb and data.messages:
        #     data.outb = data.messages.pop(0)
        # if data.outb:
        #     print('sending', repr(data.outb), 'to connection', data.connid)
        #     sent = sock.send(data.outb)  # Should be ready to write
        #     data.outb = data.outb[sent:]


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
