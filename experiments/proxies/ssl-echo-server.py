import socket
import threading
import ssl

verbose = False
mutex = threading.Lock()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s = ssl.wrap_socket(s,
                    keyfile='PATH TO PRIVATE KEY',
                    certfile='PATH TO CERT',
                    server_side=True)
s.bind(('', 443))
s.listen(1024)


def handle_connection(conn):
    resp_body = b''
    try:
        conn.settimeout(1)
        while True:
            try:
                conn_data = conn.recv(4096)
                if not conn_data:
                    break
                else:
                    resp_body += conn_data
            except socket.timeout:
                break

        response_headers = b"HTTP/1.1 200 OK\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Length: " + str(
            len(resp_body)).encode() + b"\r\n\r\n"
        conn.sendall(response_headers + resp_body)
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
    except Exception as exception:
        if verbose:
            print(resp_body)
            print("echo-server exception in handle_connection: {}".format(exception))


while True:
    try:
        conn, addr = s.accept()
        thread = threading.Thread(target=handle_connection, args=(conn,))
        thread.start()
    except Exception as exception:
        if verbose:
            print("echo-server exception in accept loop: {}".format(exception))

