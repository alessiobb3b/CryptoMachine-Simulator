# Importing required libraries and modules
from ipywidgets import interact  # For creating interactive widgets
from matplotlib import pyplot as plt  # For plotting data visualization
import time, math, json, random, hmac, hashlib, struct, base64, os, warnings  # Miscellaneous utilities
from datetime import datetime
from sequence.kernel.timeline import Timeline  # SEQUENCE library: timeline management
from sequence.topology.node import QKDNode  # SEQUENCE library: quantum key distribution node
from sequence.components.optical_channel import QuantumChannel, ClassicalChannel  # SEQUENCE library: optical communication
from sequence.qkd.BB84 import pair_bb84_protocols  # SEQUENCE library: BB84 QKD protocol
from sequence.qkd.cascade import pair_cascade_protocols  # SEQUENCE library: Cascade protocol for QKD error correction
from sequence.kernel.process import Process  # SEQUENCE library: process definition
from sequence.kernel.event import Event  # SEQUENCE library: event management
from sequence.utils.encoding import time_bin, polarization  # SEQUENCE library: encoding methods
import numpy as np  # For numerical operations
from Crypto.Random import get_random_bytes  # For generating secure random bytes
from abc import ABC, abstractmethod  # For defining abstract base classes
with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=UserWarning)
    from pqc.kem import kyber512 as kyber  # Post-quantum cryptography: Kyber KEM
from pqc.kem import mceliece6960119 as kemalg  # Post-quantum cryptography: McEliece KEM
from Crypto.Hash import SHA3_256, SHA3_512, SHAKE256  # Hashing algorithms
from enum import Enum  # For defining enumerations
from pqc.sign import dilithium2 as dilithium  # Post-quantum signature: Dilithium
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Cryptography: AES encryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Cryptography: PBKDF2 for key derivation
from cryptography.hazmat.primitives import hashes  # Cryptography: Hashing
from cryptography.hazmat.backends import default_backend  # Cryptography: Backend for primitives

# Utility class for managing variables and initializing them
class utilities():
    def __init__(self):
        pass

    def initializeVariables(self, mainKey, less=False):
        """
        Initialize simulation variables for different keys.
        :param mainKey: Main keys for which variables are to be initialized.
        :param less: Boolean to limit the variables initialized.
        :return: Initialized variable dictionaries.
        """
        # Prepare dictionaries and lists for various simulation metrics
        simTime, errors, errors0, thr0, thr1, protocolResults, jsonEncodedResults, meanErrorRatesArr = [{}, {}, {}, {}, {}, [], {}, []]
        
        # Initialize all dictionaries with keys corresponding to the input main keys
        for k in mainKey:
            simTime[k] = []
            errors[k] = []
            errors0[k] = []
            thr0[k] = []
            thr1[k] = []
        
        # Return a subset of variables if 'less' is True
        return [simTime, errors, thr0, errors0, thr1, protocolResults, jsonEncodedResults, meanErrorRatesArr] if not less else [simTime, errors, thr0]

# HOTP (HMAC-based One-Time Password) class for OTP generation and validation

class authenticationModule():
    def __init__(self, secret):
        self.hotp = self.HOTP(secret)
        self.dilithium = dilithium
        self.currentHOTP = None
    def __getHOTP(self):
        return self.hotp
    def __getDilithium(self):
        return self.dilithium
    def __setCurrentHOTP(self, currentHOTP):
        self.currentHOTP = currentHOTP
    def __getCurrentHOTP(self):
        return self.currentHOTP
    def __generateHOTP(self):
        self.__setCurrentHOTP(self.__getHOTP().generateOtp())
        return self.__getCurrentHOTP()
    def generateDilithiumAuthenticatedHOTP(self, privateKey):
        return dilithium.sign(self.__generateHOTP().encode("utf-8"), privateKey), self.__getCurrentHOTP()
    def checkAuthenticatedHOTP(self, signedHOTP, publicKey):
        self.__setCurrentHOTP(self.__getHOTP().generateOtp())
        try:
            dilithium.verify(
                signedHOTP,
                self.__generateHOTP().encode("utf-8"),
                publicKey,
            )
        except:
            exit("Invalid signature")
        return self.__getCurrentHOTP() 
    
    class HOTP:
        def __init__(self, secret, counter=0, digits=6):
            """
            Initialize the HOTP instance.
            :param secret: A shared secret key for HMAC (bytes).
            :param counter: Initial counter value (int).
            :param digits: Number of digits in the generated OTP (int).
            """
            self.secret = secret  # Store the shared secret key
            self.counter = counter  # Initialize the counter value
            self.digits = digits  # Set the desired number of digits in the OTP

        def generateOtp(self):
            """
            Generate an OTP using the current counter value.
            :return: OTP (string).
            """
            # Convert the counter to an 8-byte array in big-endian format
            counter_bytes = struct.pack(">Q", self.counter)

            # Generate an HMAC using SHA1 and the secret key
            hmac_hash = hmac.new(self.secret, counter_bytes, hashlib.sha1).digest()

            # Extract a dynamic binary code from the HMAC
            offset = hmac_hash[-1] & 0x0F
            binary_code = (
                ((hmac_hash[offset] & 0x7F) << 24)
                | ((hmac_hash[offset + 1] & 0xFF) << 16)
                | ((hmac_hash[offset + 2] & 0xFF) << 8)
                | (hmac_hash[offset + 3] & 0xFF)
            )

            # Compute the OTP by taking the binary code modulo 10^digits
            otp = binary_code % (10 ** self.digits)
            return f"{otp:0{self.digits}d}"  # Return OTP as a zero-padded string

        def validateOtp(self, otp, lookahead=1):
            """
            Validate an OTP against the current counter value.
            :param otp: OTP to validate (string).
            :param lookahead: Number of future counter values to consider (int).
            :return: True if OTP is valid, False otherwise (bool).
            """
            # Iterate through current and future counter values
            for i in range(lookahead + 1):
                test_counter = self.counter + i
                test_otp = HOTP(self.secret, test_counter, self.digits).generate_otp()
                if test_otp == otp:  # Check if the OTP matches
                    self.counter = test_counter + 1  # Increment counter after validation
                    return True
            return False  # Return False if no match is found

# AES256 encryption/decryption class
class AES256:
    def __init__(self, seed=""):
        """
        Initialize the AES256Encryption class with a seed.
        :param seed: A secret seed used for key derivation.
        """
        self.seed = seed  # Store the provided seed

    def setSeed(self, seed):
        """
        Set or update the seed value.
        :param seed: New seed value (string or bytes).
        """
        self.seed = seed

    def __getSeed(self):
        """
        Retrieve the seed as a byte array.
        :return: Byte-encoded seed.
        """
        return self.seed.encode() if isinstance(self.seed, str) else self.seed

    def _derive_key(self, salt: bytes) -> bytes:
        """
        Derive a cryptographic key using PBKDF2 with the given salt.
        :param salt: A random salt for key derivation.
        :return: A 256-bit derived key.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Key length: 256 bits
            salt=salt,
            iterations=100000,  # Number of PBKDF2 iterations
            backend=default_backend(),
        )
        return kdf.derive(self.__getSeed())

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using AES-256-GCM.
        :param plaintext: The plaintext to encrypt.
        :return: Encrypted message as a base64-encoded string.
        """
        salt = os.urandom(16)  # Generate a 16-byte random salt
        key = self._derive_key(salt)  # Derive the encryption key
        iv = os.urandom(12)  # Generate a 12-byte initialization vector
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()  # Encrypt the data
        encrypted_message = base64.b64encode(salt + iv + encryptor.tag + ciphertext).decode()
        return encrypted_message  # Return base64-encoded encrypted message

    def decrypt(self, encrypted_message: str) -> str:
        """
        Decrypt an AES-256-GCM encrypted message.
        :param encrypted_message: Base64-encoded encrypted message.
        :return: Decrypted plaintext.
        """
        data = base64.b64decode(encrypted_message)  # Decode the base64 string
        salt = data[:16]  # Extract the salt
        iv = data[16:28]  # Extract the initialization vector
        tag = data[28:44]  # Extract the GCM authentication tag
        ciphertext = data[44:]  # Extract the ciphertext

        key = self._derive_key(salt)  # Derive the key using the extracted salt
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()  # Decrypt the ciphertext
        return plaintext.decode()  # Return the plaintext as a string

# Asset class to manage cryptographic assets like public keys and HOTPs
class Asset:
    def __init__(self, publicKey):
        """
        Initialize the Asset with a public key and an HOTP module.
        :param publicKey: Public key associated with the asset.
        """
        self.cryptoMachinepublicKey = publicKey  # Store the public key
        self.HOTPModule = authenticationModule(b"supersecretkey123")  # Initialize an HOTP module with a static secret
        self.lastMessage = "" # Holds the last message

    def __getAuthenticationModule(self):
        """
        Access the HOTP module.
        :return: HOTP module instance.
        """
        return self.HOTPModule

    def __getCryptoMachinePublicKey(self):
        """
        Retrieve the public key.
        :return: Public key.
        """
        return self.cryptoMachinepublicKey

    def authenticateCryptoMachine(self, signedHOTP):
        return self.__getAuthenticationModule().checkAuthenticatedHOTP(signedHOTP, self.__getCryptoMachinePublicKey())
    
    def notify(self):
        """
        Notify the recipient asset that a new incoming message has been received.
        """
        print("[!] Recipient Asset notified of a new Incoming Message. Asking fot its content!")
    
    def setMessage(self, message):
        """
        Set the received message.
        :param message: Received message.
        """
        self.lastMessage = message
    
    def getLastMessage(self):
        """
        Retrieve the received message.
        :return: Received message.
        """
        return self.lastMessage

# Enumeration for selecting PQC modules
class chosenPQCModule(Enum):
    KYBER = 0  # CRYSTALS-Kyber
    MCELIECE = 1  # McEliece

# Enumeration for choosing key exchange strategies
class possibleStrategies(Enum):
    STATIC_STRATEGY = 0  # Static parameters-based strategy
    ALWAYS_TRY_STRATEGY = 1  # Attempt QKD before fallback

# Enumeration for defining QKD node roles
class QKDNodes(Enum):
    ALICE = 1  # Represents Alice
    BOB = 2  # Represents Bob

# Class representing a QKD endpoint (Alice or Bob)
class QKDEndpoint:
    def __init__(self, name, file="config.json"):
        """
        Initialize a QKDEndpoint with parameters loaded from a configuration file.
        :param name: The name of the endpoint (Alice or Bob).
        :param file: Configuration file containing QKD parameters.
        """
        with open(file, 'r') as f:
            config = json.load(f)["qkdParameters"]  # Load QKD parameters from the config file
        self.name = name  # Endpoint name
        self.simTime = config["simTime"]  # Simulation time (in ms)
        self.keySize = config["keyDim"]  # Dimension of the generated keys
        self.attenuation = config["attenuation"]  # Fiber attenuation (in dB/km)
        self.polarizationFidelity = config["polarizationFid"]  # Polarization fidelity
        self.distance = config["distance"]  # Fiber distance (in meters)
        self.lsParams = config["ls_params"]  # Light source parameters
        self.detectorParams = config["detector_params"]  # Detector parameters
        self.ccdly = config["ccDelay"]  # Classical channel delay (in ms)
        self.encodingSchema = config["encodingScheme"]  # Encoding scheme (time-bin/polarization)
        self.measuringVariable = config["keyDim"]  # Measurement variable
        self.node = None  # Placeholder for the QKD node instance

    # Getter for simulation time
    def getSimTime(self):
        return self.simTime

    # Getter for the last shared key
    def getLastSharedKey(self):
        return self.getHandle().protocol_stack[1].valid_keys[0]

    # Getter for key size
    def getKeySize(self):
        return self.keySize

    # Getter for attenuation
    def getAttenuation(self):
        return self.attenuation

    # Getter for polarization fidelity
    def getPolarizationFidelity(self):
        return self.polarizationFidelity

    # Getter for distance
    def getDistance(self):
        return self.distance

    # Getter for light source parameters
    def getLsParams(self):
        return self.lsParams

    # Getter for detector parameters
    def getDetectorParams(self):
        return self.detectorParams

    # Getter for encoding scheme
    def getEncodingSchema(self):
        return self.encodingSchema

    # Private setter for encoding schema
    def __setEncodingSchema(self, encodingSchema):
        self.encodingSchema = encodingSchema

    # Private setter for the node
    def __setNode(self, node):
        self.node = node

    # Getter for the node instance
    def getHandle(self):
        return self.node

    # Private getter for the endpoint name
    def __getName(self):
        return self.name

    def setupNode(self, tl):
        """
        Set up the QKD node with the specified encoding schema and parameters.
        :param tl: The simulation timeline instance.
        """
        # Determine the encoding schema
        match self.getEncodingSchema():
            case "time_bin":
                self.__setEncodingSchema(time_bin)  # Use time-bin encoding
            case _:
                self.__setEncodingSchema(polarization)  # Default to polarization encoding

        # Create and configure the QKD node based on the endpoint's name
        match self.__getName():
            case QKDNodes.ALICE:
                self.__setNode(QKDNode("alice", tl, encoding=self.getEncodingSchema()))
                self.getHandle().set_seed(1010)  # Set random seed for reproducibility
                for name, param in self.getLsParams().items():
                    self.getHandle().update_lightsource_params(name, param)
            case QKDNodes.BOB:
                self.__setNode(QKDNode("bob", tl, encoding=self.getEncodingSchema()))
                self.getHandle().set_seed(1010)  # Set random seed for reproducibility
                for i in range(len(self.getDetectorParams())):
                    for name, param in self.getDetectorParams()[i].items():
                        self.getHandle().update_detector_params(i, name, param)

# Class for managing QKD sessions between two endpoints
class QKDManager:
    def __init__(self, alice, bob):
        """
        Initialize the QKDManager with two endpoints (Alice and Bob).
        :param alice: QKDEndpoint instance representing Alice.
        :param bob: QKDEndpoint instance representing Bob.
        """
        self.alice = alice  # Store Alice's endpoint
        self.bob = bob  # Store Bob's endpoint

    # Private getter for Alice's endpoint
    def getAlice(self):
        return self.alice

    # Private getter for Bob's endpoint
    def getBob(self):
        return self.bob

    def qkdBB84QEC(self):
        """
        Execute the BB84 QKD protocol with Cascade error correction.
        """
        # Retrieve Alice and Bob's endpoints
        alice = self.getAlice()
        bob = self.getBob()

        # Initialize the simulation timeline with Alice's simulation time
        tl = Timeline(alice.getSimTime() * 1e9)
        tl.show_progress = True  # Enable progress display during simulation

        # Set up QKD nodes for Alice and Bob
        alice.setupNode(tl)
        bob.setupNode(tl)

        # Pair BB84 and Cascade protocols
        pair_bb84_protocols(alice.getHandle().protocol_stack[0], bob.getHandle().protocol_stack[0])
        pair_cascade_protocols(alice.getHandle().protocol_stack[1], bob.getHandle().protocol_stack[1])

        # Configure classical and quantum channels
        cc0 = ClassicalChannel("cc_sender_recipient", tl, distance=alice.getDistance())
        cc1 = ClassicalChannel("cc_recipient_sender", tl, distance=bob.getDistance())
        cc0.set_ends(alice.getHandle(), bob.getHandle().name)
        cc1.set_ends(bob.getHandle(), alice.getHandle().name)
        qc0 = QuantumChannel("qc_sender_recipient", tl, attenuation=alice.getAttenuation(),
                             distance=alice.getDistance(), polarization_fidelity=alice.getPolarizationFidelity())
        qc1 = QuantumChannel("qc_recipient_sender", tl, attenuation=bob.getAttenuation(),
                             distance=bob.getDistance(), polarization_fidelity=bob.getPolarizationFidelity())
        qc0.set_ends(alice.getHandle(), bob.getHandle().name)
        qc1.set_ends(bob.getHandle(), alice.getHandle().name)

        # Initialize and connect key managers for error correction
        keyManagerNode1 = self.KeyManagerQEC(tl, alice.getKeySize(), 1)
        keyManagerNode1.lower_protocols.append(alice.getHandle().protocol_stack[1])
        alice.getHandle().protocol_stack[1].upper_protocols.append(keyManagerNode1)
        keyManagerNode2 = self.KeyManagerQEC(tl, bob.getKeySize(), 1)
        keyManagerNode2.lower_protocols.append(bob.getHandle().protocol_stack[1])
        bob.getHandle().protocol_stack[1].upper_protocols.append(keyManagerNode2)

        # Start the simulation and record execution time
        tl.init()
        keyManagerNode1.send_request()
        tick = time.time()
        tl.run()
        print("Execution time %.2f sec" % (time.time() - tick))

        # Calculate new error rate with Cascade QEC
        errorRates = []
        for i, key in enumerate(keyManagerNode1.keys):
            counter = 0
            diff = key ^ keyManagerNode2.keys[i]
            for j in range(keyManagerNode1.keysize):
                counter += (diff >> j) & 1
            errorRates.append(counter)

        self.qkdSaveJsonData(alice, errorRates, keyManagerNode1)
        return errorRates

    def qkdSaveJsonData(self, protocolResults, errorRates, keyManagerNode):
        """
        Save protocol results and metrics in JSON format.
        :param protocolResults: QKD protocol results.
        :param errorRates: Error rates observed during QKD.
        :param keyManagerNode: KeyManager instance for error correction.
        """
        # Initialize experiment index and calculate metrics
        i = 0
        meanErrorRate1 = np.mean(errorRates) * 100  # Layer 1 mean error rate in percentage
        meanErrorRate0 = protocolResults.getHandle().protocol_stack[0].error_rates  # Layer 0 mean error rate
        meanThroughput1 = protocolResults.getHandle().protocol_stack[1].throughput  # Throughput for Layer 1
        meanThroughput0 = np.mean(protocolResults.getHandle().protocol_stack[0].throughputs)  # Layer 0 throughput
        exchangedKey = protocolResults.getHandle().protocol_stack[0].key  # Shared exchanged key

        # Prepare data for JSON encoding
        val, jsonEncodedResults = {}, {}
        jsonEncodedResults["Experiment" + str(i)] = {}
        jsonEncodedResults["Experiment" + str(i)]["Settings Values"] = {
            "Key Dimension": protocolResults.getKeySize(),
            "Fiber Attenuation": protocolResults.getAttenuation(),
            "Polarization Fidelity": protocolResults.getPolarizationFidelity(),
            "Distance": protocolResults.getDistance(),
            "Light Source Parameters": protocolResults.getLsParams(),
            "Detector Parameters": protocolResults.getDetectorParams(),
        }
        jsonEncodedResults["Experiment" + str(i)]["protocolResults"] = [val]
        jsonEncodedResults["Experiment" + str(i)]["protocolResults"].append({"Exchanged Key": exchangedKey})
        jsonEncodedResults["Experiment" + str(i)]["protocolResults"].append({"Mean Error Percentage Layer 0": meanErrorRate0[1]})
        jsonEncodedResults["Experiment" + str(i)]["protocolResults"].append({"Mean Error Percentage Layer 1": meanErrorRate1})
        jsonEncodedResults["Experiment" + str(i)]["protocolResults"].append({"Mean Throughput Layer 0": meanThroughput0})
        jsonEncodedResults["Experiment" + str(i)]["protocolResults"].append({"Mean Throughput Layer 1": meanThroughput1})
        jsonEncodedResults["Experiment" + str(i)]["protocolResults"].append({"Execution Time": keyManagerNode.times})
        jsonEncodedResults["Experiment" + str(i)]["protocolResults"].append({"Latency": protocolResults.getHandle().protocol_stack[0].latency})

        current_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        directory = "./"
        filename = f"{directory.rstrip('/')}/data_{current_time}.json"
        
        # Write the dictionary to the JSON file
        with open(filename, 'w') as json_file:
            json.dump(jsonEncodedResults, json_file, indent=4)

    # Class for managing key distribution and error correction (KeyManager for QEC)
    class KeyManagerQEC:
        def __init__(self, timeline, keysize, num_keys):
            """
            Initialize the KeyManager for Quantum Error Correction (QEC).
            :param timeline: Simulation timeline instance.
            :param keysize: Size of the key in bits.
            :param num_keys: Number of keys to generate.
            """
            self.timeline = timeline  # Store the simulation timeline
            self.lower_protocols = []  # List to hold lower-level protocols
            self.keysize = keysize  # Size of the keys to be generated
            self.num_keys = num_keys  # Number of keys to generate
            self.keys = []  # List to store generated keys
            self.times = []  # List to store the times of key generation events

        def send_request(self):
            """
            Request key generation from the lower-level protocols.
            """
            for protocol in self.lower_protocols:
                protocol.push(self.keysize, self.num_keys)  # Request keys from each protocol

        def pop(self, key):
            """
            Receive a generated key from a lower-level protocol.
            :param key: The generated key.
            """
            self.keys.append(key)  # Append the generated key to the list
            self.times.append(self.timeline.now() * 1e-9)  # Record the current time in seconds

# Abstract base class for exchange strategy
class exchangeProtocolStrategy(ABC):
    @abstractmethod
    def strategy(self, machine):
        """
        Define the strategy for key exchange.
        :param machine: CryptoMachine instance executing the strategy.
        """
        pass

    def getStrategyName(self):
        """
        Retrieve the name of the strategy.
        """
        pass

# Static parameters detection strategy
class staticParametersDetectionStrategy(exchangeProtocolStrategy):
    def strategy(self, machine):
        """
        Evaluate fiber parameters and determine the key exchange method.
        :param machine: CryptoMachine instance.
        """
        # Retrieve QKD parameters
        distance, attenuation, polarizationFidelity, keyDim = machine.getQKDParameters()
        
        # Determine if QKD is feasible
        isQKDPossible = (attenuation < 0.01) and (polarizationFidelity > 0.90) and (distance < 15000) and (keyDim < 2048)
        if isQKDPossible:
            print("\t- Fiber Assessment established a favorable environment for QKD. Key Exchange will proceed via QKD!")
            machine.KEMviaQKD()  # Proceed with QKD
        else:
            print("\t- Fiber Assessment established an adverse environment for QKD. Key Exchange will switch through PQC!")
            machine.KEMviaPQC()  # Switch to PQC

    def getStrategyName(self):
        return "Static Fiber's Parameters Evaluation Strategy"

# Attempt QKD before fallback strategy
class tryExchangeBeforeChangeStrategy(exchangeProtocolStrategy):
    def strategy(self, machine):
        """
        Attempt QKD first, and fallback to PQC if QKD fails.
        :param machine: CryptoMachine instance.
        """
        #try:
        print("\t- A Key Exchange attempt via QKD will be made!")
        machine.KEMviaQKD()  # Try QKD first
        except:
            print("\t- QKD Exchange Failed!!! Key Exchange will switch through PQC!")
            machine.KEMviaPQC()  # Fallback to PQC

    def getStrategyName(self):
        return "Always Try to Exchange Before Changing Strategy"

# Class representing a cryptographic machine
# Class representing a cryptographic machine
class cryptoMachine:
    def __init__(self, PQCModule, publicKeySender, publicKeyRecipient, qkdNode, strategy, privateKey, asset, manager=None):
        """
        Initialize a CryptoMachine instance.
        :param PQCModule: PQC module (Kyber or McEliece).
        :param publicKey: Public key of the machine.
        :param qkdNode: QKD endpoint (Alice or Bob).
        :param strategy: Exchange strategy for key management.
        :param privateKey: Private key of the machine (optional).
        :param asset: Associated Asset instance (optional).
        :param manager: QKDManager instance (optional).
        """
        self.qkdNode = qkdNode # Initialize QKD endpoint
        self.PQCModule = PQCModule  # Set the PQC module
        self.twin = None  # Placeholder for the twin machine
        self.sharedKey = ""  # Shared key placeholder
        self.privateKey = privateKey  # Store private key
        self.publicKeys = [publicKeySender, publicKeyRecipient]  # Store public key
        self.authenticationModule = [authenticationModule(b"supersecretkey123"), authenticationModule(b"supersecretkey321")]  # Two Authentication modules
        self.AES256Module = AES256("")  # Initialize AES256 module
        self.currentHOTP = None  # Placeholder for current HOTP
        self.asset = asset  # Associated asset
        self.message = ""  # Message placeholder
        self.manager = manager  # QKDManager instance
        self.strategy = strategy  # Key exchange strategy
        self.messagesQueue = {} # Encrypted Messages received Queue

    # Setting and retrieving the twin CryptoMachine
    def setTwin(self, twin):
        self.twin = twin

    def __getTwin(self):
        return self.twin
    
    def __getMessageFromQueue(self, key):
        return self.messagesQueue[key]
    
    def __getMessageQueue(self):
        return self.messagesQueue
    
    def __deleteMessageFromQueue(self):
        if self.__getMessageQueue():
            del self.__getMessageQueue()[self.getSharedKey()]
    
    def __addMessageToQueue(self, message):
        self.__getMessageQueue()[self.getSharedKey()] = message

    def __getPrivateKey(self):
        return self.privateKey
    
    def __getPublicKeys(self, i):
        return self.publicKeys[i]

    # Getters and Setters for various properties
    def getQKDParameters(self):
        return (
            self.getQkdNode().getDistance(),
            self.getQkdNode().getAttenuation(),
            self.getQkdNode().getPolarizationFidelity(),
            self.getQkdNode().getKeySize(),
        )

    def setQKDManager(self, qkdManager):
        self.manager = qkdManager

    def getQkdNode(self):
        return self.qkdNode

    def getSharedKey(self):
        return self.sharedKey

    def __setSharedKey(self, key):
        self.sharedKey = key

    def __getStrategy(self):
        return self.strategy

    def __getPQCModule(self):
        return self.PQCModule

    def __getAES256Module(self):
        return self.AES256Module
    
    def __getAuthenticationModule(self, device):
        match device:
            case "Asset":
                return self.authenticationModule[0]
            case "Twin":
                return self.authenticationModule[1]

    def __getAsset(self):
        return self.asset

    def getMessage(self):
        return self.message

    def __setMessage(self, message):
        self.message = message

    def __setCurrentHOTP(self, hotp):
        self.currentHOTP = hotp

    def __getCurrentHOTP(self):
        return self.currentHOTP
    
    def authenticateCryptoMachine(self, signedHOTP):
        return self.__getAuthenticationModule("Twin").checkAuthenticatedHOTP(signedHOTP, self.__getPublicKeys(0))

    # Key Exchange methods
    def KEMviaPQC(self):
        """
        Perform key exchange using PQC.
        """
        print(f"[!] Starting Key Exchange via PQC using {self.PQCModule.getAlgoName()}...")
        publicKey, privateKey = self.PQCModule.generate_keypair()
        ciphertext = self.twin.__recipientSetSharedKey(False, publicKey)
        key = self.PQCModule.decap(ciphertext, privateKey)
        self.__setSharedKey(key)
        print("\t- Key Exchange Completed!")

    def KEMviaQKD(self):
        """
        Perform key exchange using QKD.
        """
        print(f"[!] Starting Key Exchange via QKD...")
        self.manager.qkdBB84QEC()
        self.__setSharedKey(str(self.qkdNode.getLastSharedKey()))
        self.twin.__recipientSetSharedKey(True)

    def __recipientSetSharedKey(self, isQKD, publicKey=None):
        """
        Set the shared key on the recipient side.
        :param isQKD: Whether the key is exchanged via QKD.
        :param publicKey: Public key (if using PQC).
        """
        if not isQKD:
            sharedSecretEnc, ciphertext = self.PQCModule.encap(publicKey)
            self.__setSharedKey(sharedSecretEnc)
            return ciphertext
        else:
            self.__setSharedKey(str(self.qkdNode.getLastSharedKey()))

    def __authenticateRecipient(self, device):
       signedHOTP, hotp = self.__getAuthenticationModule(device).generateDilithiumAuthenticatedHOTP(self.__getPrivateKey())
       self.__setCurrentHOTP(hotp)
       assert self.__getAsset().authenticateCryptoMachine((signedHOTP)) if device == "Asset" else self.__getTwin().authenticateCryptoMachine((signedHOTP)) == self.__getCurrentHOTP()

    # Message Exchange
    def shareEncryptedMessage(self):
        """
        Share an encrypted message between CryptoMachines.
        """
        print("[!] Starting Secret Message Exchange Session...")
        print("\t- Assessing Asset's Identity!")
        self.__authenticateRecipient("Asset")
        print("\t- Asset's Identity Confirmed!")

        self.__setMessage(self.__getAsset().getLastMessage())

        print("\t- Assessing Coupled Crypto-Machine Identity!")
        self.__authenticateRecipient("Twin")
        print("\t- Coupled Crypto-Machine Identity Confirmed!")

        print("[!] Assessing Fiber Channel Parameters...")
        self.__getStrategy().strategy(self)

        print("[!] Starting Message Encryption...")
        assert self.getSharedKey() == self.twin.getSharedKey()
        self.__getAES256Module().setSeed(self.getSharedKey())
        encryptedMessage = self.__getAES256Module().encrypt(self.getMessage())
        self.__getTwin().deliverReceivedMessage(encryptedMessage)
        self.__setMessage("")
        print("\t- Message Encrypted and Successfully Shared!")

    def deliverReceivedMessage(self, encryptedMessage):
            self.__addMessageToQueue(encryptedMessage)
            print("[!] Received a new Message. Alerting Asset")
            self.__getAsset().notify()
            print("\t- Assessing Recipient Asset's Identity!")
            self.__authenticateRecipient("Asset")
            print("\t- Asset's Identity Confirmed!")
            self.__getAsset().setMessage(self.__decryptSharedMessage(self.__getMessageFromQueue(self.getSharedKey())))
            print("\t- Message Decrypted Shared with Asset!")
            self.__deleteMessageFromQueue()
        
    def __decryptSharedMessage(self, encryptedMessage):
            """
            Decrypt a shared message received from the twin.
            :param encryptedMessage: Encrypted message.
            :return: Decrypted plaintext.
            """
            self.__getAES256Module().setSeed(self.getSharedKey())
            self.__setMessage(self.__getAES256Module().decrypt(encryptedMessage))
            return self.getMessage()

# Factory class to create PQC modules (Kyber or McEliece)
class PQCModulesFactory:
    def __init__(self, module):
        """
        Initialize the PQCModulesFactory with a specific module type.
        :param module: The PQC module type (Kyber or McEliece).
        """
        self.module = module  # Store the selected module type

    def getModule(self):
        """
        Retrieve the corresponding PQC module.
        :return: Instance of the specified PQC module.
        """
        match self.module:
            case chosenPQCModule.KYBER.value:
                return KyberKEMModule()  # Return Kyber module
            case chosenPQCModule.MCELIECE.value:
                return mcelieceKEMModule()  # Return McEliece module

# Abstract base class for PQC Key Encapsulation Mechanisms (KEM)
class PQCKEMInterface(ABC):
    @abstractmethod
    def generate_keypair(self):
        """
        Abstract method to generate a public-private keypair.
        :return: A tuple containing the public and private keys.
        """
        pass

    @abstractmethod
    def encap(self, public_key):
        """
        Abstract method to encapsulate a shared secret.
        :param public_key: Public key for encapsulation.
        :return: A tuple containing the shared secret and ciphertext.
        """
        pass

    @abstractmethod
    def decap(self, ciphertext, private_key):
        """
        Abstract method to decapsulate a shared secret.
        :param ciphertext: Ciphertext to decapsulate.
        :param private_key: Private key for decapsulation.
        :return: The shared secret.
        """
        pass

    @abstractmethod
    def getAlgoName(self):
        """
        Abstract method to retrieve the algorithm name.
        :return: The name of the PQC algorithm as a string.
        """
        pass


# Implementation of the Kyber KEM module
class KyberKEMModule(PQCKEMInterface):
    def generate_keypair(self):
        """
        Generate a Kyber keypair.
        :return: A tuple containing the public and private keys.
        """
        return kyber.keypair()

    def encap(self, public_key):
        """
        Encapsulate a shared secret using the public key.
        :param public_key: Public key for encapsulation.
        :return: A tuple containing the shared secret and ciphertext.
        """
        return kyber.encap(public_key)

    def decap(self, ciphertext, private_key):
        """
        Decapsulate a shared secret using the ciphertext and private key.
        :param ciphertext: Ciphertext from encapsulation.
        :param private_key: Private key for decapsulation.
        :return: The shared secret.
        """
        return kyber.decap(ciphertext, private_key)

    def getAlgoName(self):
        """
        Retrieve the name of the algorithm.
        :return: "CRYSTALS-Kyber".
        """
        return "CRYSTALS-Kyber"

# Implementation of the McEliece KEM module
class mcelieceKEMModule(PQCKEMInterface):
    def generate_keypair(self):
        """
        Generate a McEliece keypair.
        :return: A tuple containing the public and private keys.
        """
        return kemalg.keypair()

    def encap(self, public_key):
        """
        Encapsulate a shared secret using the public key.
        :param public_key: Public key for encapsulation.
        :return: A tuple containing the shared secret and ciphertext.
        """
        return kemalg.encap(public_key)

    def decap(self, ciphertext, private_key):
        """
        Decapsulate a shared secret using the ciphertext and private key.
        :param ciphertext: Ciphertext from encapsulation.
        :param private_key: Private key for decapsulation.
        :return: The shared secret.
        """
        return kemalg.decap(ciphertext, private_key)

    def getAlgoName(self):
        """
        Retrieve the name of the algorithm.
        :return: "McEliece".
        """
        return "McEliece"

# Factory class to create strategy instances
class strategyFactory:
    def createStrategy(self, strategy):
        """
        Create a strategy instance based on the specified type.
        :param strategy: Strategy type (Static or Always Try).
        :return: An instance of the corresponding strategy class.
        """
        match strategy:
            case possibleStrategies.STATIC_STRATEGY.value:
                return staticParametersDetectionStrategy()  # Static strategy
            case possibleStrategies.ALWAYS_TRY_STRATEGY.value:
                return tryExchangeBeforeChangeStrategy()  # Always try strategy

def createCryptoMachnesCouple(module, strategy):
    """
    Create and couple two CryptoMachines (Alice and Bob).
    :param module: PQC module type (Kyber or McEliece).
    :param strategy: Strategy type for key exchange.
    :return: A tuple containing the two coupled CryptoMachines.
    """
    print("[!] Creating Crypto-Machines...")
    
    # Generate a public-private keypair using Dilithium
    publicKeySender, privateKeySender = dilithium.keypair()
    publicKeyRecipient, privateKeyRecipient = dilithium.keypair()

    # Instantiate the PQCModulesFactory
    factory = PQCModulesFactory(module)

    # Create the strategy instance using the factory
    strategyFactoryInstance = strategyFactory()

    senderAsset = Asset(publicKeySender)
    recipientAsset = Asset(publicKeyRecipient)

    # Assign a QKDManager for managing QKD sessions
    manager = QKDManager(QKDEndpoint(QKDNodes.ALICE), QKDEndpoint(QKDNodes.BOB))

    # Instantiate the sender (Alice) and recipient (Bob)
    sender = cryptoMachine(
        factory.getModule(),
        publicKeySender,
        publicKeyRecipient,
        manager.getAlice(),
        strategyFactoryInstance.createStrategy(strategy),
        privateKeySender,
        senderAsset,
        manager
    )

    recipient = cryptoMachine(
        factory.getModule(),
        publicKeySender,
        publicKeyRecipient,
        manager.getBob(),
        strategyFactoryInstance.createStrategy(strategy),
        privateKeyRecipient,
        recipientAsset
    )

    # Set each other's twin (pair the machines)
    sender.setTwin(recipient)
    recipient.setTwin(sender)

    

    senderAsset.setMessage(input("Provide a message to share over the Encrypted Channel: "))

    return sender, recipient, senderAsset, recipientAsset

if __name__ == "__main__":
    # Load configuration from a JSON file
    with open("config.json", 'r') as f:
        config = json.load(f)
    
    # Create coupled CryptoMachines (Alice and Bob) based on config parameters
    sender, recipient, senderAsset, recipientAsset = createCryptoMachnesCouple(
        config["executionParameters"]["pqcModule"], 
        config["executionParameters"]["executionStrategy"]
    )

    print("\t- Crypto-Machines created, coupled and connected!")

    # Start the secret message exchange process
    sender.shareEncryptedMessage()
    
    print("[!] Exchange correctly achieved...")
    print(f"\t- Sent message: {senderAsset.getLastMessage()}")
    print(f"\t- Received message: {recipientAsset.getLastMessage()}")
    print(f"\t- Shared Key Sender-Side:   {sender.getSharedKey()}")
    print(f"\t- Shared Key Receiver-Side: {recipient.getSharedKey()}")
