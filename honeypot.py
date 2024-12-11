import socket
import logging
import re

# Configure logging
logging.basicConfig(
    filename="honeypot.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

HONEYPOT_IP = "0.0.0.0"
HONEYPOT_PORT = 9999

def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HONEYPOT_IP, HONEYPOT_PORT))
        server.listen(5)
        logging.info("Honeypot started on " + HONEYPOT_IP + ":" +
str(HONEYPOT_PORT))

        while True:
            client_socket, client_address = server.accept()
            logging.info("Connection attempt from " +
client_address[0] + ":" + str(client_address[1]))
            handle_connection(client_socket, client_address)
    except KeyboardInterrupt:
        logging.info("Honeypot shutting down.")
    except Exception as e:
        logging.error("Error: " + str(e))
    finally:
        server.close()

def handle_connection(client_socket, client_address):
    try:
        client_socket.settimeout(2)  # Timeout for port scan detection
        client_socket.sendall(b"Welcome to the honeypot!\n")
        try:
            data = client_socket.recv(1024).decode("utf-8")
            logging.info("Data received from " + client_address[0] +
":" + str(client_address[1]) + ": " + data)

            if "admin" in data or "root" in data:
                logging.warning("Potential brute force attempt from "
+ client_address[0] + ":" + str(client_address[1]))

            if "../" in data:
                logging.warning("Potential directory traversal attempt
from " + client_address[0] + ":" + str(client_address[1]))

            if re.search(r"SELECT|DROP|INSERT|UPDATE|DELETE", data,
re.IGNORECASE):
                logging.warning("Potential SQL injection attempt from
" + client_address[0] + ":" + str(client_address[1]))
        except socket.timeout:
            detect_port_scan(client_socket, client_address)
        client_socket.sendall(b"Interaction logged. Goodbye!\n")
    except Exception as e:
        logging.error("Error handling connection from " +
client_address[0] + ":" + str(client_address[1]) + ": " + str(e))
    finally:
        client_socket.close()

def detect_port_scan(client_socket, client_address):
    logging.warning("Potential port scanning detected from " +
client_address[0] + ":" + str(client_address[1]))
    client_socket.close()

if __name__ == "__main__":
    start_honeypot()
