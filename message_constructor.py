import struct
from Crypto.Cipher import PKCS1_OAEP as OAEP
from hashlib import sha256

class MessageConstructor:
  max_server_chunks = 10
  server_chunk_size = 300
  def __init__(self, message, receipient, receipient_pk):
    self.message = message
    self.receipient = receipient
    self.receipient_pk = receipient_pk
    self.cipher = OAEP.new(self.receipient_pk)
    self.messageid = sha256()
    self.client_chunk_size = 200
    self.messageid.update(message)
    
  def split_utf8(self, message, n):
    while len(message) > n:
      k = n
      while (ord(message[k]) & 0xc0) == 0x80:
        k -= 1
      yield message[:k]
      message = message[k:]
    yield message
  
  def create_header(self, number_of_chunks):
    """Create the header for the encrypted message"""
    n = 'CLIENT_CHUNK: {}'.format(server_chunk_size)
    chunks = 'NUM_CHUNKS: {}'.format(number_of_chunks)
    s = struct.pack('I>', n, chunks)
    return s
  
  def encrypt_message_for_receipient(self):
    chunked_messages = self.split_utf8(self.message, self.client_chunk_size)
    encrypted_messages = [self.cipher.encrypt(m) for m in chunked_messages]
    client_chunks = len(encrypted_messages)
    return encrypted_messages, client_chunks