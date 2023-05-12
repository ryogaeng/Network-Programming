# Create a TCP server and client using socket library to Develop a game "Guess the number"

import socket, argparse    # Import socket libraries for TCP socket programming
import random    # Import random module to generate random number
import sys    # Import sys to access functions that related to system

MAX_BYTES = 1024


def server(interface, port):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # Create listening socekt for server
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    # To ensure normal execution of the server program, the 'SO_REUSEADDR' option is used to allow a new socket to reuse the port number previously used
    server_sock.bind((interface, port))
    server_sock.listen(1)    # Waiting for client's connection request
    
    print("Waiting for client connection....")

    active_sock, client_addr = server_sock.accept()    # Accept() method accepts the client's connection request, and returns an active_sock (commonly known as active socket or connected socket) for communication with the client, along with the client's address.
    print("Client connected : ", client_addr)    # Print client's address and port#

    x = random.randint(1, 10)    # Generate a random natural number between 1 and 10 using the random module.
    print("Random number : ", x)    # Print random number generated by the server
    
    while True:
        data = active_sock.recv(MAX_BYTES).decode()    # Receive data(maybe "start") from the client
        if data == "start":
            active_sock.sendall("s".encode())    # Send "s" to inform that the game is starting
            break
        else:    # If the data is not a "start"
            active_sock.sendall("\'Server\' >> Invalid request. If you want to start the game, please send me a \"start\" message.".encode())    # Send a message to re-enter
    
    try:
        cnt = 0    # variable 'cnt' to count 5 chances
        while True:
            guess_str = active_sock.recv(MAX_BYTES).decode()    # A number(string type) from client 
            if guess_str == '':    # If guess_str is empty(blank) 
                continue    # back to the beginning of while loop
            guess = int(guess_str)    # string to int   
            if guess == x:    # If the number sent by the client is correct
                active_sock.sendall("a".encode())    # Send "a" to inform that the client is correct
                break    # escape while loop
            cnt+=1    # deduct one chance
            if cnt == 5:    # Use all five chances
                active_sock.sendall(str(x).encode())    # Send a x(string) generated by the server to notify answer number
                break    # escape while loop
            
            if guess < x:    # If the number sent by client is smaller than random number
                active_sock.sendall("b".encode())    # Send "b" to inform that the random number is higher
            elif guess > x:    # If the number sent by client is higher than random number
                active_sock.sendall("c".encode())    # Send "c" to inform that the random number is smaller

    except ConnectionResetError:    
        # Exception handling for when the other side forces the socket connection, or when the network connection is disconnected unexpectedly, etc..
        print("Unexpectedly disconnected(maybe disconnected by peer).")

    except Exception as e:
        # Exception handling for the rest of the case
        print(e)

    finally:
        active_sock.close()    # close the connected socket
        server_sock.close()    # close the listening socekt

        
def client(host, port):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # Create TCP socekt for client

    try:
        client_sock.connect((host, port))    # Request a connection from the server
    except ConnectionRefusedError:
        # Exception handling that occurs when a client tries to connect before the server runs
        print("Failed to connect to the server.")
        sys.exit()    # to terminate python interpreter (=closing program)

    while True:
        send_start = input("Send a \"start\" message to start the game : ")    # Request to start the game
        client_sock.sendall(send_start.encode())    # Send variable 'send_start'(string)
        start_to_game = client_sock.recv(MAX_BYTES).decode()    # Receive the answer of request
        if start_to_game == "s":    # If receive message "s"
            print("OK. Let's start the game. Guess a natural number between 1 to 10. You have only 5 chances!")    # Ready for game
            break
        else:    # Receive a message other than "s"
            print(start_to_game)    # Print the message from the server and go back to beginning of while loop and re-request to start the game
        
    try:
        cnt = 1    # variable 'cnt' to count 5 chances and the number of attempt
        while True:
            guess = input("Attempt " + str(cnt) + " : ")    # input string type / show the number of attempt
            try:
                guess_int = int(guess)    # string to int
                if guess_int < 1 or guess_int > 10:    # if client input the number out of range
                    raise ValueError
                else:    # An acceptable number
                    cnt+=1    # deduct one chance
                    client_sock.sendall(str(guess_int).encode())    # int to string / Send to server
            except ValueError:
                # Exception handling that occurs when an input that does not meet a given condition is received
                print("Invalid input. Please input a natural number between 1 to 10.")
                continue
                
            reply_of_server = client_sock.recv(MAX_BYTES).decode()    # response of server that is one of the following: "a", "b", "c", str(x)
            
            if reply_of_server == "a":    # If the response is "a", the game is successful
                print("Congratulations you did it.")    
                break    # escape while loop
            
            if cnt == 6:    # If client used up all five chances
                print("Fail to guess the number. The answer number was " + reply_of_server + ".")    # Tell what random number is generated by the server
                break    # escape while loop
            
            if reply_of_server == "c":    # "c" inform that the number sent by the client is larger than random number
                print("You Guessed too high!")
            elif reply_of_server == "b":     # "b" inform that the number sent by the client is smaller than random number
                print("You guessed too small!")

    except ConnectionResetError:
        # Exception handling for when the other side forces the socket connection, or when the network connection is disconnected unexpectedly, etc..
        print("Unexpectedly disconnected(maybe disconnected by peer).")

    except Exception as e:
        # Exception handling for the rest of the case
        print(e)

    finally:
        client_sock.close()    # close client socket
        
        
if __name__ == '__main__':    # main program
    choices = {'client': client, 'server': server}    # If the user selects either client or server, the corresponding function (client() or server()) will be executed
    parser = argparse.ArgumentParser(description='Send and receive over TCP')    # The argparse module is used to process command-line arguments
    parser.add_argument('role', choices=choices, help='which role to play')    # determines whether the user will act as a client or server.
    parser.add_argument('host', help='interface the server listens at;' ' host the client sends to')    # Adds a 'host' and uses the hostname or IP address for the server to listen on and the client to send to
    parser.add_argument('-p', metavar='PORT', type=int, default=1061, help='TCP port (default 1061)')    # Adds a 'PORT' and sets the default value to 1061
    args = parser.parse_args()    # Parses the command-line arguments and stores them in the 'args' object
    function = choices[args.role]    # Assigns either the client or server function to the "function" variable depending on the value of the 'args.role' argument
    function(args.host, args.p)    # Executes the function assigned to the "function" variable
