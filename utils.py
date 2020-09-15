from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from flask import flash

import hashlib
import json

from flask import Flask, jsonify, request
import requests
from time import time
from urllib.parse import urlparse
from uuid import uuid4

from datetime import datetime
import collections


class Patient:
    def __init__(self, name, private_key=""):
        if private_key == "":
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048 * 4,
                backend=default_backend()
                )
        else:
            self.private_key = private_key = serialization.load_pem_private_key(
                                                                             private_key,
                                                                             password=None,
                                                                             backend=default_backend())

        self.public_key = self.private_key.public_key()
        
        self.name = name
        
        
    def Encrypt(self, message):
        ciphertext = self.public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
        return ciphertext
    
    
    def Decrypt(self, ciphertext):
        plaintext = self.private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
        return plaintext

    def RetName(self):
        return self.name


class Doctor:
    def __init__(self, name, private_key=""):
        self.name = name
        
        if private_key == "":
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
                )

        else:
            self.private_key = private_key = serialization.load_pem_private_key(
                                                                             private_key,
                                                                             password=None,
                                                                             backend=default_backend())

        self.public_key = self.private_key.public_key()
        
    def Sign(self, message):
        message = bytes(message, "utf-8")
        signature = self.private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
        hashes.SHA256()
        )
        return signature
    
    def Verify(self, message, signature):
        message = bytes(message, "utf-8")
        try:
            self.public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
            hashes.SHA256()
            )
            return True
        except:
            print("invalid signature")
            return False

    def RetName(self):
        return self.name


class EHR:
    def __init__(self, doctor = Doctor, patient = Patient, data = ""):
        self.patient = patient
        self.doctor = doctor
        self.data = data
    
    
    def ToDict(self):
        dict1 = {"doctor": self.doctor.RetName(), "patient": self.patient.RetName(), "sign": self.sign}
        return dict1

    def ToHash(self):
        block_string = json.dumps({"patient":self.patient, "doctor": self.doctor, "data":self.data}, default=str).encode()
        return hashlib.sha256(block_string).hexdigest()
        



class Transaction:
    def __init__(self, doctor = Doctor, patient = Patient, ehr = ""):
        self.doctor = doctor
        self.patient = patient
        self.ehr = ehr
    def ToDict(self):
        transaction = {"doctor": self.doctor.name, "patient": self.patient.name, "ehr": self.ehr}
        return transaction



class Block:
    def __init__(self, nonce = 0, tstamp = None, prev_hash = None, hash = None, transaction = Transaction):
        self.nonce = nonce
        self.tstamp = tstamp
        self.prev_hash = prev_hash
        self.transaction = transaction
        if hash == None:
            self.hash = self.calcHash()
        else:
            self.hash = hash
    def calcHash(self):
        block_string = json.dumps({"nonce":self.nonce, "tstamp":self.tstamp, "transaction":self.transaction.ToDict(), 
                                 "prev_hash":self.prev_hash}, default=str).encode()
        return hashlib.sha256(block_string).hexdigest()
    
    def mine(self, difficulty = 4):
        compare = "0" * difficulty
        self.hash = self.calcHash()
        while str(self.hash[:difficulty]) != compare:
            self.nonce += 1
            self.hash = self.calcHash()
        return self.hash
    
    def ToDict(self):
        block = {"nonce":self.nonce,
                 "tstamp":self.tstamp,
                 "transaction":self.transaction.ToDict(), 
                 "prev_hash":self.prev_hash,
                 "hash":self.hash}
        return block



class BlockChain:
    def __init__(self):
        self. pending_transactions = []
        self.chain = []
        self.generateGenesisBlock()
        self.difficulty = 4
        self.reward = 100
        self.nodes = set()


    def isChainValid(self, chain):
        """
        Determine if a given blockchain is valid
        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            # Check that the hash of the block is correct
            last_block_hash = last_block.calcHash()
            if block.prev_hash != last_block_hash:
                flash("prev hash != last block hash")
                return False

            # Check that the Proof of Work is correct
            if str(last_block.calcHash()[:self.difficulty]) != "0" * self.difficulty:
                print("proof not valid")
                return False

            last_block = block
            current_index += 1

        return True

    

    def replaceChain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                bchain = []
                for temp in chain:
                    doctor = Doctor(name = temp["transaction"]["doctor"])
                    patient = Patient(name = temp["transaction"]["patient"])
                    ehr = temp["transaction"]["ehr"]
                    transaction = Transaction(doctor, patient, ehr)
                    block = Block(hash = temp["hash"], nonce = temp["nonce"], prev_hash = temp["prev_hash"], transaction = transaction, tstamp = temp["tstamp"])
                    bchain.append(block)
                if length > max_length and self.isChainValid(bchain):
                    max_length = length
                    longest_chain = bchain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False

    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)


    
    
    
        
    def PrintChain(self):
        for block in self.chain:
            pprint.pprint(block.ToDict())
            
    def newBlock(self, block = Block):
        #if block.hash == None:
        
        #if block.prev_hash == None:
        block.prev_hash = self.chain[-1].hash
        #if block.tstamp == None:
        block.tstamp = datetime.utcnow()
        block.mine()
        #else:
        #block.tstamp = tstamp
        self.chain.append(block)
        #transaction = Transaction(patient=miner_address, doctor="Genesis", ehr="Genesis")
        #self.pending_transactions.append(transaction)
        return block

    def generateGenesisBlock(self):
        doctor = Doctor(name = "Genesis")
        patient = Patient(name = "Genesis")
        ehr = EHR(doctor, patient, "Genesis")
        transaction = Transaction(doctor=doctor, patient=patient, ehr=ehr.ToHash())
        block = Block(transaction=transaction)
        block.mine()
        self.chain.append(block)
    
    def FinishPendingTransactions(self):
        pass


    @property
    def last_block(self):
        return self.chain[-1]


    def valid_proof(block = Block):
        """
        Validates the Proof
        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.
        """

        guess_hash = block.calcHash()
        return str(guess_hash[:4]) == "0000"

def GetPrivateKey(key):
    private_key = key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm = serialization.NoEncryption())
    return private_key

def GetPublicKey(key):
    public_key = key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return public_key