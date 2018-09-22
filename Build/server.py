#!/usr/bin/env python3

import socket
import click
import signal
import time
import sys
import selectors

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
# PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

@click.command()
@click.option('--server_ip', default=None)
@click.option('--port', '-l', default=None
              help="Add the server port to which the socket must bind")
@click.option('--input', "<", default=None
              help="This option specifies the input file")
@click.option('--output', ">", default=None,
              help="This option specifies the output file")
def main(server_ip, port, input, output)
    if server_ip:

def createServer(server_address, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serverSocket:
            sel = selectors.DefaultSelector()
            serverSocket.bind((server_address, int(port)))
            serverSocket.listen()
            print(f"Server Listening on address {server_address} and port {port}....")
            serverSocket.setblocking(False)
            sel.register(serverSocket, selectors.EVENT_READ, data=none)
            while True:
                events = sel.select(timeout=None)
                print("These are the events", events)
                for key, mask in events:
                    if key.data is None:
                        accept_wrapper(key.fileobj)
                    else:
                        service_connection(key, mask)
    except KeyboardInterrupt:
        signal.signal(signal.SIGINT, sigint_handler)

def sigint_handler(signum, frame):
    sys.exit("On your command, the script has been terminated.")

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
            sent = sock.send(data.outb)  # Should be ready to write
            data.outb = data.outb[sent:]


def createClient():


if  __name__ == "__main__":
    main()
