import socket, json, base64, os

SERVER_HOST = 'localhost'
SERVER_PORT = 8080
SAVE_DIRECTORY = '/home/receiver/received_files' # where the file will be saved.

def handle_file_transfer_request(client_socket, client_address):
    # Read full data from socket in chunks
    chunks = []
    while True:
        chunk = client_socket.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)

    # put all chunks into one string and decode as JSON
    request = b''.join(chunks).decode()
    request_data = json.loads(request)

    # check if the request is to send a file
    if request_data['action'] == 'send_file':
        recipient_email = request_data['data']['recipient']
        file_name = request_data['data']['file_name']
        file_data = base64.b64decode(request_data['data']['file_data'])
        print(f"Contact '{recipient_email}' is sending a file: {file_name}. Accept (y/n)?")
        response = input()

        if response.lower() == 'y':
            print(f"Saving file '{file_name}'...")

            # Makes sure if directory exists
            if not os.path.exists(SAVE_DIRECTORY):
                os.makedirs(SAVE_DIRECTORY)
            file_path = os.path.join(SAVE_DIRECTORY, file_name)
            with open(file_path, 'wb') as file:
                file.write(file_data)

            print(f"File '{file_name}' has been successfully transferred.")
        else:
            print("File transfer has been denied.")

    client_socket.close()

def start_server():
    # Set up the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection established with {client_address}")
        handle_file_transfer_request(client_socket, client_address)

if __name__ == '__main__':
    start_server()
