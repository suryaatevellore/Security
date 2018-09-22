#!/usr/bin/python
import socket
from threading import Thread
from SocketServer import ThreadingMixIn

HOST = '192.168.56.106'
TCP_PORT = 60001
BUFFER_SIZE = 1024


class ClientThread(Thread):

    def __init__(self, ip, port, sock):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.sock = sock

    def run(self):
        filename = 'mytext.txt'
        f = open(filename, 'wb')
        while True:
            data = self.sock.recv(1024)
            if not data:
                f.close()
                # self.sock.close()
                break
            f.write(data)
        self.sock.sendall("File received")
        self.sock.close()


tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcpsock.bind((HOST, TCP_PORT))
threads = []

while True:
    tcpsock.listen(5)
    (conn, (ip, port)) = tcpsock.accept()
    conn.settimeout(2)
    newthread = ClientThread(ip, port, conn)
    newthread.start()
    threads.append(newthread)

for t in threads:
    t.join()
