import socket
import pickle
import multiprocessing as mp


HEADER_LENGTH = 10

IP = "10.0.0.2"
PORT = 1234


def create_server_socket(whitelist):
    print("Creating socket")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((IP, PORT))
    server_socket.listen()

    state = "PCMDiscoveryRequest"
    start_server(server_socket, whitelist)


def start_server(server_socket, whitelist):
    print("Starting server")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address} has been established.")

        state = "PCMDiscoveryRequest"

        while True:
            if state == "PCMDiscoveryRequest":
                print("State: ", state)

                message_header = client_socket.recv(HEADER_LENGTH)
                message_length = int(message_header.decode("utf-8"))

                msg = client_socket.recv(message_length)
                pcm_network_address = pickle.loads(msg)
                print(pcm_network_address)

                state = "PCMDiscoveryResponse"

            if state == "PCMDiscoveryResponse":
                print("State: ", state)

                msg = pickle.dumps(whitelist)
                msg = bytes(f'{len(msg):<{HEADER_LENGTH}}', "utf-8") + msg
                client_socket.send(msg)

                state = "ConnectionEstablished"

            if state == "ConnectionEstablished":
                print("Connection established")
                while True:
                    message_header = client_socket.recv(HEADER_LENGTH)
                    message_length = int(message_header.decode("utf-8"))

                    msg = client_socket.recv(message_length)
                    d = pickle.loads(msg)
                    print(d)


if __name__ == '__main__':
    whitelist = ["10.0.0.1", "10.0.0.2", "10.0.0.4"]

    p1 = mp.Process(target=create_server_socket, args=(whitelist,))
    p1.start()

