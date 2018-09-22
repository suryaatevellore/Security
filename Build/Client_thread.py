#!/usr/bin/python
import socket

# TCP_IP = 'localhost'
HOST = '192.168.56.106'
TCP_PORT = 60001

BUFFER_SIZE = 1024

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((HOST, TCP_PORT))

filename='/tmp/f'
f = open(filename, 'rb')

while True:
    chunk = f.read(BUFFER_SIZE)
    if not chunk:
        print "File transfer completed"
        f.close()
        break
    socket.send(chunk)

c = socket.recv(BUFFER_SIZE)
print c
socket.close()
print('connection closed')
