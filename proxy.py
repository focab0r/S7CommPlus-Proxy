from scapy.all import *
from proxy_utils.utils import save_tls_packet_to_file
from proxy_utils.checks import *
from proxy_utils.decode import *
from tls import *
from scapy.supersocket import StreamSocket
import connection
import threading
from colorama import Fore, Style


# Restart all variables to zero
# Needed when client dies
def set_con_to_zero(code):
	if code == 1:
		connection.clientPort = 0
		# TCP Server #
		connection.server_data_buffer = deque()
		connection.server_mutex = 0
		connection.server_socket = 0
		connection.server_queue = deque()
		# TLS Server #
		connection.server_ssl_obj = 0
		connection.server_bio_in = 0
		connection.server_bio_out = 0
		connection.server_aux_data = 0
		connection.server_bio_mutex = 0
	elif code == 2:
		# TCP Client #
		connection.client_data_buffer = deque()
		connection.client_mutex = 0
		connection.client_socket = 0
		connection.client_queue = deque()
		# TLS Client #
		connection.client_create_tls = 0
		connection.client_ssl_obj = 0
		connection.client_bio_in = 0
		connection.client_bio_out = 0
		connection.client_bio_mutex = 0


def manage_data(code):
	if code == 1:
		pck_list = connection.server_queue
	elif code == 2:
		pck_list = connection.client_queue
	while len(pck_list) != 0:
		pck = pck_list.popleft()
		print(f'[{"Server" if code == 1 else "Client"}]: Processing new packet: {pck}')
		if is_empty_COPT(pck):
			print(f'[{"Server" if code == 1 else "Client"}]: Marked as an empty COTP')
			continue							# Empty COTP
		elif is_COTP_handshake(pck):
			print(Fore.GREEN + f'[{"Server" if code == 1 else "Client"}]: Marked as a COTP header' + Style.RESET_ALL)
			save_data(pck, code)				# COTP handshake
		elif is_s7(pck):
			print(f'[{"Server" if code == 1 else "Client"}]: Marked as a S7 packet')
			save_data(pck, code)				# S7 not encrypted
		elif is_tls_handshake(pck):
			print(Fore.GREEN + f'[{"Server" if code == 1 else "Client"}]: Marked as a TLS handshake' + Style.RESET_ALL)
			manage_tls_handshake(pck, code)     # TLS handshake
		elif is_tls(pck):
			print(f'[{"Server" if code == 1 else "Client"}]: Marked as a TLS packet')
			manage_tls_packet(pck, code)        # TLS package detected
		else:
			print(Fore.RED + f'[{"Server" if code == 1 else "Client"}]: Unable to find a suitable packet type' + Style.RESET_ALL)
			save_tls_packet_to_file(pck, code)	# Unknown packet type
			save_data(pck, code)


# Main program of the server-item thread 
# It will be represented by code 1
def proxy_server():
	while True:
		server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server_sock.bind((connection.listenIP, connection.listenPort))
		server_sock.listen()
		connection.server_mutex = threading.Lock()
		connection.server_bio_mutex = threading.Lock()
		print(Fore.GREEN + "[Server] Server is awaiting connections" + Style.RESET_ALL)
		sock, addr = server_sock.accept()
		print("[Server] Connection received")
		sock.setblocking(False)
		connection.server_socket = StreamSocket(sock, Raw)
		while True:
			try:
				raw_data = bytes(connection.server_socket.recv())		# Read data from socket server
				connection.server_queue = parse_tpkt_packets(raw_data)
				manage_data(1)											# Manage data received
			except BlockingIOError:										# If there is no data, check queue to send
				while len(connection.client_data_buffer) > 0:
					data_to_send = read_data(1)
					print(f"[Server] Sending data from the queue... [{data_to_send}]")
					connection.server_socket.send(data_to_send)
			except EOFError:											# Client has died
				print(Fore.RED + "[CRITICAL] [Server] The client has died. Restarting..." + Style.RESET_ALL)
				set_con_to_zero(1)
				connection.kill_client = 1
				break


# Main program of the client-item thread
# It will be represented by code 2
def proxy_client():
	while True:
		client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client_sock.connect((connection.serverIP, connection.serverPort))
		connection.client_mutex = threading.Lock()
		connection.client_bio_mutex = threading.Lock()
		client_sock.setblocking(False)
		connection.client_socket = StreamSocket(client_sock, Raw)
		print(Fore.GREEN + "[Client] Client is ready" + Style.RESET_ALL)
		while True:
			if connection.client_create_tls == 1:						# Check if the server-item has already done the TLS handshake
				create_tls_client()											# Start TLS handshake
				connection.client_create_tls = 2
			if connection.kill_client == 1:								# Check if client has died
				print(Fore.RED + "[CRITICAL] [Client] Connection has been killed. Restarting..." + Style.RESET_ALL)
				set_con_to_zero(2)
				connection.kill_client = 0
				break
			try:
				raw_data = bytes(connection.client_socket.recv())		# Read data from socket client
				connection.client_queue = parse_tpkt_packets(raw_data)
				manage_data(2)											# Manage data received
			except BlockingIOError:										# If there is no data, check queue to send
				while len(connection.server_data_buffer) > 0:
					data_to_send = read_data(2)
					print(f"[Client] Sending data from the queue... [{data_to_send}]")
					connection.client_socket.send(data_to_send)
			except EOFError:											# Server has died
				print(Fore.RED + "[CRITICAL] [Server] The client has died" + Style.RESET_ALL)
				exit(1)
