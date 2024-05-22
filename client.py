import socket
import hmac
import hashlib
import logging

# Setup logging
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
# Create a logger object
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Setup formatter
formatter = logging.Formatter(LOG_FORMAT)

# Setup file handler
file_handler = logging.FileHandler("clientDebug.log", mode='w')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Setup console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Set the secret key directly in the code
SECRET_KEY = 'secretkey'.encode()

# Function to create an HMAC for a given message
def createHMAC(message):
    # Create an HMAC object using the secret key and the SHA-256 hashing algorithm
    return hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()

# Function to send a message to the server
def sendMessage(message):
    try:
        # Create a TCP/IP socket
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect the socket to the server on localhost at port 65432
        clientSocket.connect(('localhost', 65432))

        # Generate the HMAC for the message
        messageHMAC = createHMAC(message)
        # Combine the message and the HMAC separated by "::"
        data = f"{message}::{messageHMAC}"
       
        # Log the message and its HMAC
        logger.debug(f"Sending message with HMAC: [{message} | {messageHMAC}]")

        # Send the encoded message and HMAC to the server
        clientSocket.sendall(data.encode())
        # Receive the server's response (up to 1024 bytes)
        response = clientSocket.recv(1024)
       
        # Log the server's response
        logger.info("Server response: %s", response.decode())

    except ConnectionError as e:
        # Log a connection error if it occurs
        logger.error(f"Connection error: {e}")
    except Exception as e:
        # Log any other unexpected errors
        logger.critical(f"Unexpected error: {e}")
    finally:
        # Close the socket to clean up
        clientSocket.close()

if __name__ == "__main__":
    try:
        # Prompt the user to enter a message
        message = input("Enter your message: ")
        if message:
            # Send the message if the user entered message
            sendMessage(message)
        else:
            # Log a warning if no message was entered
            logger.warning("No message entered. Exiting.")
    except KeyboardInterrupt:
        # Log info message if the user interrupts the program
        logger.info("Client interrupted by user. Exiting.")
