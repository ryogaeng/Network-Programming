import argparse
import socket
import ssl # Access to Transport Layer Security
import threading # Constructs higher-level threading interfaces
import json
import zlib 
from logging import basicConfig, getLogger, INFO # Used for creating logs

# Define the number of clients
MAX_BYTES = 5

basicConfig(level=INFO)
# basicConfig(level=INFO) is used to set up the root logger at the specified level, which in this case is INFO.
logger = getLogger(__name__)
# Create a logger

def judge_alphabet(char): # Checks if the 'char' is an alphabet
    return ('A' <= char <= 'Z') or ('a' <= char <= 'z')

def judge_upper(char): # Checks if the 'char' is an uppercase
    return 'A' <= char <= 'Z'

def convert_lower(char): # Converts the 'char' to lowercase if it is an uppercase
    if judge_upper(char):
        return chr(ord(char) + 32)
    return char

def convert_upper(char): # Converts the 'char' to uppercase if it is an lowercase
    if not judge_upper(char):
        return chr(ord(char) - 32)
    return char

# Receives data from the client, performs the task specified in the data, and sends the result back to the client
def detail_handling(conn): 
    
    # Continuously receives data from the client in 1024 bytes until no data is received
    while True:
        data = conn.recv(1024)
        if not data:
            break

        # Decompress and decode the message
        message = json.loads(zlib.decompress(data)) 

        task = message.get('task')
        
        # If the task is 'ping', then try to get the IP address of the domain
        if task == 'ping':
            domain = message.get('domain')
            try:
                ip_address = socket.gethostbyname(domain)
            except Exception as e:
                logger.error(f'Error during DNS lookup: {e}')
                ip_address = 'Error during DNS lookup'
            response = {'ip_address': ip_address}
            
        # Toggle the case of each character in the string if the action is 'togle_string'  
        elif task == 'toggle_string':
            s = message.get('string')
            toggled_string = ""
            for char in s:
                if judge_alphabet(char):
                    if judge_upper(char):
                        toggled_string += convert_lower(char)
                    else:
                        toggled_string += convert_upper(char)
                else:
                    toggled_string += char  # if not a letter, simply append to the result
            response = {'string': toggled_string}
        else:
            response = {'error': 'Invalid task'}

        # The response is converted into JSON format, encoded into bytes, compressed, and then sent back to the client
        conn.sendall(zlib.compress(json.dumps(response).encode('utf-8')))

    conn.close() # The connection with the client is closed
    logger.info('The connection has been terminated')

    
# Set up a server that listens for connections on a specified host and port, and uses specified certificate and key files for SSL encryption.
def server(host, port, certfile, keyfile, cafile=None):
    # Set CLIENT_AUTH, which means it is intended for authenticating clients
    purpose = ssl.Purpose.CLIENT_AUTH
    context = ssl.create_default_context(purpose, cafile=cafile)
    context.load_cert_chain(certfile, keyfile=keyfile)

    # A TCP socket is created and bound to the specified host and port
    # It is set to listen for incoming connections, with a backlog of up to MAX_BYTES connections.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, port))
        sock.listen(MAX_BYTES)
        logger.info(f'Server listening at {host}:{port}')

        # Continuously accepts new connections
        while True:
            client_socket, addr = sock.accept()
            logger.info(f'Connected from {addr}')
            conn = context.wrap_socket(client_socket, server_side=True) # Socket is wrapped in an SSL
            threading.Thread(target=detail_handling, args=(conn,), daemon=True).start() # A new thread is created, so that multiple clients can be handled simultaneously

# Set up a client that connects to a server at a specified host and port, and uses a specified CA certificate file for SSL encryption
def client(host, port, cafile=None):
    # Set SERVER_AUTH, which means it is intended for authenticating server
    purpose = ssl.Purpose.SERVER_AUTH
    context = ssl.create_default_context(purpose, cafile=cafile)

    # A connection that wrapped in an SSL is created to the specified host and port
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            # To prompt the user to enter a task continuously
            # Select the task that the user wants to do
            while True:
                task = input('Enter the task you want (ping/toggle_string/quit): ')
                if task == 'quit':
                    break
                if task == 'ping':
                    domain = input('Enter the domain that you want to get ip address: ')
                    message = {'task': task, 'domain': domain}
                elif task == 'toggle_string':
                    string = input('Enter the string for which you want to change the case: ')
                    message = {'task': task, 'string': string}
                else:
                    print('Invalid task')
                    continue

                # Convert into JSON format, encode into bytes, compress, and then send to the server
                ssock.sendall(zlib.compress(json.dumps(message).encode('utf-8')))
                # Receive a response from the server, decompress, decode it 
                response = json.loads(zlib.decompress(ssock.recv(1024)))
                # print it
                print(response)

if __name__ == '__main__':
    # Set up argument parsing
    parser = argparse.ArgumentParser(description='Secure client and server')
    # Specifying host and port number
    parser.add_argument('host', help='hostname or IP address')
    parser.add_argument('port', type=int, help='TCP port number')
    # Specifying the CA certificate file
    parser.add_argument('-a', metavar='cafile', default=None,
                        help='authority: path to CA certificate PEM file')
    # Use the '-s' and '-k' options to apply server certificate file and server key file 
    parser.add_argument('-s', metavar='certfile', default=None,
                        help='run as server: path to server PEM file')
    parser.add_argument('-k', metavar='keyfile', default=None,
                        help='run as server: path to server key PEM file')
    args = parser.parse_args()

     # Check if the '-s' and '-k' options were used, and if they were, it runs as a server, otherwise it runs as a client
    if args.s and args.k:
        server(args.host, args.port, args.s, args.k, args.a)
    else:
        client(args.host, args.port, args.a)

   





