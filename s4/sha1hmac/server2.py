import socket
from urllib.parse import parse_qs, urlparse
import time
from pathlib import Path

# Set 4 Challenge 32 - Break HMAC-SHA1 with a slightly less artificial timing leak
# Code mostly generated using a mix of Gemini and Claude, with some parts
# cleaned up and the insecure timing code manually-written
# Changed only the sleep time insecurecmp

hmacs = dict()

def getlocalhmac(filename):
    try:
        with open("files/" + filename + ".hmac", "r") as fp:
            h = fp.read()
            h = h.strip()
    except:
        h = None

    return h

def insecurecmp(a, b):
    # compare two hashes character by character with a delay of 50ms
    if len(a) != len(b):
        return False
    try:
        a = bytes.fromhex(a)
        b = bytes.fromhex(b)
    except:
        return False

    for x,y in zip(a,b):
        if x != y:
            return False
        # time.sleep(0.05) # sleep for 50ms
        time.sleep(0.003) # sleep for a shorter duration

    return True

def gethmacs():
    dir = Path("files")
    global hmacs
    for filepath in dir.glob("*.hmac"):
        # print(filepath)
        h = filepath.read_text()
        basename = filepath.stem
        # print(h, basename)
        hmacs[basename] = h

def handle_request(client_sock):
    global hmacs
    request_data = client_sock.recv(1024).decode("utf-8")
    if not request_data:
        client_sock.close()
        return

    # Extract the HTTP request line
    lines = request_data.split("\r\n")
    request_line = lines[0]
    parts = request_line.split(" ")
    if len(parts) < 2:
        client_sock.close()
        return

    path = parts[1]
    parsed_url = urlparse(path)
    if parsed_url.path != "/test":
        status_code = 404
    else:
        query_params = parse_qs(parsed_url.query)
        filename = query_params.get("file", [None])[0]
        provided_hmac = query_params.get("hmac", [None])[0]
        # print(provided_hmac)
        if filename and provided_hmac:
            # Note: In a production environment, sanitize the filename to
            # prevent path traversal attacks.
            # local_hmac = getlocalhmac(filename) # option 1: read from file
            local_hmac = hmacs[filename] # option 2: read hmacs from memory
            # print(local_hmac)
            if local_hmac == None:
                status_code = 404
            elif insecurecmp(local_hmac, provided_hmac):
                status_code = 200
            else:
                status_code = 500

    # Construct the HTTP response
    if status_code == 200:
        status_line = "HTTP/1.1 200 OK"
        response_body = "OK: HMAC verified successfully"
    if status_code == 404:
        status_line = "HTTP/1.1 404 Not Found"
        response_body = "File Not Found"
    if status_code == 500:
        status_line = "HTTP/1.1 500 Internal Server Error"
        response_body = "Internal Server Error: HMAC mismatch"

    response = (
        f"{status_line}\r\n"
        "Content-Type: text/plain\r\n"
        f"Content-Length: {len(response_body)}\r\n"
        f"\r\n{response_body}"
    )

    client_sock.sendall(response.encode("utf-8"))
    client_sock.close()


def run_server():
    gethmacs()
    global hmacs
    # print(hmacs)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 8080))
    server.listen(5)
    print("Server running on http://127.0.0.1:8080...")

    try:
        while True:
            client_sock, addr = server.accept()
            handle_request(client_sock)
    except KeyboardInterrupt:
        print("\nShutting down server.")
    finally:
        server.close()


if __name__ == "__main__":
    run_server()
