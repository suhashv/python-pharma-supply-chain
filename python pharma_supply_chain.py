import hashlib
import time
import json
from collections import deque
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Block class representing each block in the blockchain
class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, nonce=0):
        self.index = index  # Index of the block in the chain
        self.previous_hash = previous_hash  # Hash of the previous block in the chain
        self.timestamp = timestamp  # Timestamp of the block creation
        self.transactions = transactions  # List of transactions in the block
        self.nonce = nonce  # Nonce used for proof-of-work
        self.hash = self.calculate_hash()  # Hash of the current block

    # Function to calculate the hash of the block
    def calculate_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    # Function to mine the block by solving the proof-of-work problem
    def mine_block(self, difficulty):
        while self.hash[:difficulty] != '0' * difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()

    def __repr__(self):
        return json.dumps(self.__dict__, indent=4)

# Blockchain class managing the entire chain
class Blockchain:
    def __init__(self, difficulty=2):
        self.chain = deque([self.create_genesis_block()])  # Initialize the chain with the genesis block
        self.difficulty = difficulty  # Difficulty level for mining
        self.pending_transactions = []  # List of transactions waiting to be added to the chain

    # Function to create the first block (genesis block)
    def create_genesis_block(self):
        return Block(0, "0", time.time(), "Genesis Block")

    # Function to get the latest block in the chain
    def get_latest_block(self):
        return self.chain[-1]

    # Function to add a new block to the chain
    def add_block(self, block):
        block.previous_hash = self.get_latest_block().hash
        block.mine_block(self.difficulty)
        self.chain.append(block)

    # Function to add a transaction to the list of pending transactions
    def add_transaction(self, transaction):
        if self.verify_transaction(transaction):
            self.pending_transactions.append(transaction)

    # Function to verify a transaction's signature
    def verify_transaction(self, transaction):
        signature = bytes.fromhex(transaction['signature'])
        public_key = RSA.import_key(transaction['sender_public_key'])
        h = SHA256.new(transaction['content'].encode())
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    # Function to mine all pending transactions and add them as a block to the chain
    def mine_pending_transactions(self):
        new_block = Block(len(self.chain), self.get_latest_block().hash, time.time(), self.pending_transactions)
        self.add_block(new_block)
        self.pending_transactions = []

    # Function to validate the entire chain for consistency and integrity
    def validate_chain(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
        return True

# Entity class representing participants in the supply chain (e.g., Manufacturer, Distributor, Pharmacy)
class Entity:
    def __init__(self, name):
        self.name = name
        self.key_pair = RSA.generate(2048)  # Generate RSA key pair for signing transactions

    # Function to create a signed transaction
    def create_transaction(self, recipient_public_key, content):
        h = SHA256.new(content.encode())
        signature = pkcs1_15.new(self.key_pair).sign(h)
        return {
            'sender_public_key': self.key_pair.publickey().export_key().decode(),
            'recipient_public_key': recipient_public_key.export_key().decode(),
            'content': content,
            'signature': signature.hex()
        }

# Example simulation of the supply chain

# Initialize blockchain with difficulty level 3
blockchain = Blockchain(difficulty=3)

# Create supply chain entities
manufacturer = Entity("Manufacturer")
distributor = Entity("Distributor")
pharmacy = Entity("Pharmacy")

# Manufacturer creates a transaction to send drugs to the distributor
transaction1 = manufacturer.create_transaction(distributor.key_pair.publickey(), "Drug shipment from Manufacturer to Distributor")

# Distributor creates a transaction to send drugs to the pharmacy
transaction2 = distributor.create_transaction(pharmacy.key_pair.publickey(), "Drug shipment from Distributor to Pharmacy")

# Add transactions to the blockchain
blockchain.add_transaction(transaction1)
blockchain.add_transaction(transaction2)

# Mine the pending transactions to create a new block
blockchain.mine_pending_transactions()

# Print the blockchain after mining
print("Blockchain after mining:")
for block in blockchain.chain:
    print(block)

# Validate the blockchain's integrity
print("Is blockchain valid?", blockchain.validate_chain())
