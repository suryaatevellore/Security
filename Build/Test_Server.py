#!/usr/bin/env python3

import sys
import socket
import selectors
import types
import os
import json
from Crypto.Cipher import AES

sel = selectors.DefaultSelector()
key = b'Sixteen byte key'
messages_recieved = []

def create_Message():

def accept_wrapper(sock):
    conn, addr = sock.accept()  # Should be ready to read
    print('accepted connection from', addr)
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b'', outb=b'')
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)



def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)  # Should be ready to read
        if recv_data:
            data.outb += recv_data

        else:
            print('closing connection to', data.addr)
            sel.unregister(sock)
            sock.close()
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            print('echoing', repr(data.outb), 'to', data.addr)
            messages_recieved.append(data.outb.decode())
            with open("small_file_server.txt","w") as f2:
                for item in messages_recieved:
                    f2.write(item)
            statinfo = os.stat("smallfile_client.txt")
            print("size of file", statinfo.st_size)
            sent = sock.send(data.outb)  # Should be ready to write
            data.outb = data.outb[sent:]

            print("yayyyyyyyyyyyyyy",messages_recieved,"\n")



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
