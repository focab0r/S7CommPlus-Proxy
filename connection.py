from collections import deque
#####
# Connection structure. Only one connection at a time is available
#####

serverIP = 0
serverPort = 0
clientIP = 0
clientPort = 0
listenIP = 0
listenPort = 0
remoteIP = 0

kill_client = 0


# TCP Server #
server_data_buffer = deque()
server_mutex = 0
server_socket = 0
server_queue = 0

# TCP Client #
client_data_buffer = deque()
client_mutex = 0
client_socket = 0
client_queue = 0

# TLS Server #
server_ssl_obj = 0
server_bio_in = 0
server_bio_out = 0
server_aux_data = 0
server_bio_mutex = 0

# TLS Client #
client_create_tls = 0
client_ssl_obj = 0
client_bio_in = 0
client_bio_out = 0
client_bio_mutex = 0


CERTFILE = 'keys/server.crt' # Replace with actual paths
KEYFILE = 'keys/server.key'