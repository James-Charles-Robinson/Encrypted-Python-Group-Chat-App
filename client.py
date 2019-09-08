import socket
import sys
import select
import errno
import multiprocessing
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64

def Send(my_username, client_socket, key):
    while True:
        # Wait for user to input a message
        message = input("")

        # If message is not empty - send it
        if message:
            message = message.encode('utf-8')
            f = Fernet(key)
            message = f.encrypt(message)
            # Encode message to bytes, prepare header and convert to bytes, like for username above, then send
            message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            client_socket.send(message_header + message)

def Receive(client_socket, HEADER_LENGTH, key):
    while True:
        try:
            # Now we want to loop over received messages (there might be more than one) and print them
            while True:

                # Receive our "header" containing username length, it's size is defined and constant
                username_header = client_socket.recv(HEADER_LENGTH)

                # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
                if not len(username_header):
                    print('Connection closed by the server')
                    sys.exit()

                # Convert header to int value
                username_length = int(username_header.decode('utf-8').strip())

                # Receive and decode username
                username = client_socket.recv(username_length).decode('utf-8')

                # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
                message_header = client_socket.recv(HEADER_LENGTH)
                message_length = int(message_header.decode('utf-8').strip())
                message = client_socket.recv(message_length)

                message = (Fernet(key).decrypt(message)).decode('utf-8')

                # Print message
                print(f'{username} > {message}')

        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print('Reading error: {}'.format(str(e)))
                sys.exit()

            # We just did not receive anything
            continue

        except Exception as e:
            # Any other exception - something happened, exit
            print('Reading error: '.format(str(e)))
            sys.exit()



if __name__ == '__main__':

    HEADER_LENGTH = 10

    IP = input("Server IP: ")
    PORT = 1234
    my_username = input("Username: ")
    while True:
        password = input("Password: ")
        if password == "password123":
            break
        else:
            print("Incorrect")
    password = password.encode()
    salt = b'\xe5\xfd\xcc\x17W3\xa1\xf6*\x12\'\x8a4WA"'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    print("Type to send a message")

    # Create a socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to a given ip and port
    client_socket.connect((IP, PORT))

    # Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
    client_socket.setblocking(False)

    # Prepare username and header and send them
    username = my_username.encode('utf-8')
    username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(username_header + username)

    #constantly look for messages with other process
    receiver = multiprocessing.Process(target=Receive, args=(client_socket,HEADER_LENGTH,key))
    receiver.start()
    #at same time wait for input
    Send(my_username,client_socket,key)

