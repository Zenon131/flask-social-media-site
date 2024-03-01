import socket
import threading

HOST = '127.0.0.1'
PORT = 5008
LISTEN_LIMIT = 5

def main():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HOST, PORT))
        print(f"Running server on {HOST} {PORT}")
    except:
        print(f"Unable to bind to host {HOST} and port {PORT}")
    
    server.listen(LISTEN_LIMIT)

    while 1:
        client, address = server.accept()
        print(f"Successfully connected to client {address[0]} {address[1]}")
    



if __name__ == 'main':
    main()