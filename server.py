import socket
import threading
import struct

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

batch_messages = []
clients = []
MAX_BATCH_SIZE = 20

class ThreadedServer(object):
  def __init__(self, host, port, sk):
    self.host = host
    self.port = port
    self.sk = sk
    self.cipher = PKCS1_OAEP.new(self.sk)
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.sock.bind((self.host, self.port))

  def listen(self):
    global clients
    self.sock.listen(5)
    while True:
      client, addr = self.sock.accept()
      clients.append(client)
      client.settimeout(60)
      threading.Thread(target=self.listen_to_client, args=(client, addr)).start()
  
  def listen_to_client(self, client, address):
    global batch_messages
    global clients
    encrypted_data = self.recv_msg(client)
    while encrypted_data:
      decrypted_data = self.cipher.decrypt(encrypted_data)
      batch_messages.append(decrypted_data)
      if len(batch_messages) == MAX_BATCH_SIZE:
        [self.send_msg(c, msg) for msg in batch_messages for c in clients]
        [self.send_msg(c, '') for c in clients]
        del batch_messages[:]
      encrypted_data = self.recv_msg(client)
    
  def decrypt_message(self, encrypted_message):
    return self.cipher.decrypt(encrypted_message)
  
  def send_msg(self, sock, msg):
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)

  def recv_msg(self, sock):
    raw_msgln = self.recv_all(sock, 4)
    if not raw_msgln:
      return
    msgln = struct.unpack('>I', raw_msgln)[0]
    return self.recv_all(sock, msgln)

  def recv_all(self, sock, n):
    data = b''
    while len(data) < n:
      packet = sock.recv(n - len(data))
      if not packet:
        return
      data += packet
    return data



if __name__ == '__main__':
  private_key = RSA.importKey(open('server_private_key.pem').read())
  ThreadedServer('', 8000, private_key).listen()

