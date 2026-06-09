import argparse
from netfilterqueue import NetfilterQueue
from proxy import *
from scapy import *

import connection   # Connection variable


# Arguments
parser = argparse.ArgumentParser()
parser.add_argument("-si", "--serverIP", required=True, help="Server IP to which the proxy will forward the requests")
parser.add_argument("-sp", "--serverPort", required=True, help="Server port to which the proxy will forward the requests")
parser.add_argument("-ci", "--clientIP", required=True, help="Client IP in which the proxy will listen for connection")
parser.add_argument("-li", "--listenIP", required=True, help="Listen IP of the proxy")
parser.add_argument("-lp", "--listenPort", required=True, help="Listen port of the proxy")
parser.add_argument("-ri", "--remoteIP", required=True, help="Sender IP of the proxy")

args = parser.parse_args()

# Save the arguments in the connection
connection.serverIP = args.serverIP
connection.serverPort = int(args.serverPort)
connection.clientIP = args.clientIP
connection.clientPort = 0                  # Till the first incoming packet we dont know the client connection port
connection.listenIP = args.listenIP
connection.listenPort = int(args.listenPort)
connection.remoteIP = args.remoteIP

# load_layer("tls")

t1 = threading.Thread(target=proxy_server)
t2 = threading.Thread(target=proxy_client)
t1.daemon = True            # Set the threads to dye when the main program has finished
t2.daemon = True            # Set the threads to dye when the main program has finished

try:
    print("[*] Creating server socket...")
    t1.start()
    print("[*] Creating client socket...")
    t2.start()
    t1.join()
    t2.join()
except KeyboardInterrupt:
    # TODO: Improve cleaning process
    print("[*] Cleaning...")
    connection.server_socket.close()
    connection.client_socket.close()
    print("[*] Exit")
