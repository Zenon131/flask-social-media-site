import socket
import threading

HOST = '127.0.0.1'
PORT = 5008

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect((HOST, PORT))
        print(f"Connected to server {HOST} {PORT}")
    except:
        print(f"Unable to connect to server {HOST} {PORT}")


if __name__ == 'main':
    main()