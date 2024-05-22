import socket
import hmac
import hashlib
import logging

# Setup logging
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Setup formatter
formatter = logging.Formatter(LOG_FORMAT)

# Setup file handler
file_handler = logging.FileHandler("serverDebug.log", mode='w')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Setup console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Setting the secret key directly in the code
SECRET_KEY = 'secretkey'.encode()

def verifyHMAC(message, receivedHMAC):
     # Compute the HMAC using the secret key, message, and SHA-256 hash algorithm
    computedHMAC = hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()
       # Compare the computed HMAC with the received HMAC using a constant-time comparison method
       # to mitigate timing attacks
    return computedHMAC, hmac.compare_digest(computedHMAC, receivedHMAC)

def startServer():
    try:
     # Creating a socket for the server
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.bind(('localhost', 65432))
         # Listening for a new connection
        serverSocket.listen(1)
         # Notification in the console for the server start
        print("Server started and awaiting messages...")

         # Loop to wait for new connections
        while True:
            clientSocket, addr = serverSocket.accept()
            logger.info(f"Connection from {addr}")
            
        # Console notification for waiting for a message from the client
            print("Waiting for message from client...")
             # Receiving data from the client
            data = clientSocket.recv(1024).decode()
            if not data:
            # If there is no data received, close the connection and continue waiting for new connections
                logger.warning("No data received. Closing connection.")
                clientSocket.close()
                continue

            try:
                   # Split the message and HMAC
                message, receivedHMAC = data.rsplit('::', 1)
                 # Log notification for receiving the message and HMAC
                logger.info(f"Message received with HMAC: [{message} | {receivedHMAC}]")
                logger.info("Validating HMAC...")

                 # Verify the HMAC
                computedHMAC, isValid = verifyHMAC(message.encode(), receivedHMAC)
                if isValid:
                    response = "Message verified successfully. Integrity and authenticity confirmed."
                    logger.info(response)
                    clientSocket.sendall(response.encode())
                else:
                    response = f"Invalid HMAC received. Computed HMAC: {computedHMAC}"
                    logger.warning(response)
                    clientSocket.sendall("Invalid HMAC".encode())
            except ValueError as e:
                logger.error(f"Error processing data: {e}")
                clientSocket.sendall("Error processing data".encode())

            clientSocket.close()
# Log a critical error message if any unexpected exception occurs in the server
    except Exception as e:
        logger.critical(f"Server encountered an error: {e}")
# Start the server function when the script is executed
if __name__ == "__main__":
    startServer()
