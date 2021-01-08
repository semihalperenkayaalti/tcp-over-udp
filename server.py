'''
Semih Alperen Kayaaltı
150160068
'''

import socket
import time
import random as rd
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os.path

def pad(s):
    return s + (16 - len(s) % 16) * bytes([(16 - len(s) % 16)])
def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

# Represents integers from 0-255 in one byte
def toByte(s):
    return bytes([s])

# Returns 0-255 byte to integer
def fromByte(s):
    return ord(s)
    
def decideStatus(n):
    if n == 0:
        return "HANDSHAKE"
    elif n == 1:
        return "ACK"
    else:
        return "INVALID CODE"
        
def unreliableSend(packet, sock, user, errRate):
    if errRate < rd.randint(0,100):
        sock.sendto(packet, user)
        

UDP_IP_ADDRESS = "127.0.0.1"
UDP_PORT_NO = 65432
errRate = 10 # Average Error rate of the unreliable channel
TIMEOUT = 0.0001
N = 1 # Go-back-N N

sessionKey = None
AEScipher = None
fileList = []
transmittedPackets = []
clientHasSessionKey = False
sequenceNumber = 0
SessionKeyTimeoutRetryTimes = 5
DataTransferTimeoutRetryTimes = 10

print("STARTING SERVER... \nLISTENING ON PORT 65432")

serverSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSock.bind((UDP_IP_ADDRESS, UDP_PORT_NO))
serverSock.settimeout(TIMEOUT)


while True:
    try:
        # check socket for new data
        data, user = serverSock.recvfrom(1024)
        if decideStatus(data[0]) == "HANDSHAKE":
            
            if AEScipher is not None:
                continue;
                
            print("\nHandshake Initiated by client: {}".format(user))
            
            packetLength = data[1]
            
            # extract filename and rsa public key from the socket data
            filename = data[2:].decode('utf-8').split('ssh')[0]
            rsaPublicKeyData = data[2:].decode('utf-8').split('.txt')[1]
            
            # import key instance
            rsaPublicKey = RSA.import_key(rsaPublicKeyData)
            
            print("Packet Length: {} \nFilename: {} \nRSA Public Key: {}".format(packetLength, filename, rsaPublicKeyData))
            
            # server checks if requested file exists
            if os.path.isfile(filename):
            
                print("INFO: Requested file exists... continuing")
                
                # create random 16 bytes session key
                sessionKey = get_random_bytes(16)
                
                # declare Aes cipher
                AEScipher = AES.new(sessionKey, AES.MODE_ECB)

                # open requested file
                with open(filename, 'r') as filePointer:
                    payload = filePointer.read(255)
                    while payload:
                        fileList.append(payload)
                        payload = filePointer.read(255)
                        
                # set up a transmitted packets lists for tracking packets and initialize all values to False
                # false = client has not acknowledged to receive the packet
                # true = client has acknowledged to receive the packet
                for payload in range(len(fileList)):
                    transmittedPackets.append(False)
                        
                print("INFO: Maximum payload size is 255 bytes... file will be sent in {} parts".format(len(fileList)))
                    
                # declare RSA encyrptor
                rsaEncryptor = PKCS1_OAEP.new(rsaPublicKey)
                
                # prepare the packet
                length = toByte(len(sessionKey))
                pType = toByte(0)
                packet = pType + length + sessionKey
                
                # encode the packet with RSA
                encodedPacket = rsaEncryptor.encrypt(packet);
                
                print("INFO: Session key is sent to the client")

                unreliableSend(encodedPacket, serverSock, user, errRate)
                                
            else:
                print("ERROR: Requested file does not exist...")
                exit(0);
                
        else:
            # this part can only be accessed after session keys are exchanged
            # thus data needs to be decrypted first with AES256
            data = AEScipher.decrypt(data)
            data = unpad(data)
                        
            # if client sent acknowledgement packet
            if decideStatus(data[0]) == "ACK":
                
                # reset timeout retry times variable each time client responds
                DataTransferTimeoutRetryTimes = 10
                
                # sequence number sent by client
                sequenceNumber = data[1]
                                
                # if client confirms receiving the FIN packet then server can terminate
                # to differ the first packet confirmation from FIN packet confirmation
                if sequenceNumber == 0 and transmittedPackets[len(fileList)-1]:
                    print("INFO: Transmission completed")
                    exit(0)
                
                # mark the global flag that indicates
                # if client has the session key
                elif sequenceNumber == 0 and clientHasSessionKey == False:
                    print("INFO: Client has received the session key")
                    print("INFO: Starting to send packets to client now")
                    payload = fileList[sequenceNumber]
                    packet = toByte(2) + toByte(len(payload)) + toByte(sequenceNumber) + payload.encode()
                    packet = pad(packet)
                    encodedPacket = AEScipher.encrypt(packet)
                    unreliableSend(encodedPacket, serverSock, user, errRate)
                    print("DATA: Server sends packet number {} now".format(sequenceNumber))
                    clientHasSessionKey = True
                    continue;
                    
                else:
                    print("ACK: Client confirms to receive packet number {}".format(sequenceNumber))
                    
                # client confirms the packet with the given sequence number has been received
                # so we can mark every packet before this packet and this packet as transmitted
                for packet in range(sequenceNumber+1):
                    transmittedPackets[packet] = True

                
                # client confirms receiving the last packet
                # server sends FIN packet to client
                if sequenceNumber == len(fileList) - 1:
                    packet = toByte(3) + toByte(sequenceNumber)
                    packet = pad(packet)
                    encodedPacket = AEScipher.encrypt(packet)
                    unreliableSend(encodedPacket, serverSock, user, errRate)
                    continue;
                

                # client confirmed receiving packet: sequenceNumber
                # server sends packet: sequenceNumber + 1
                payload = fileList[sequenceNumber + 1]
                packet = toByte(2) + toByte(len(payload)) + toByte(sequenceNumber+1) + payload.encode()
                packet = pad(packet)
                encodedPacket = AEScipher.encrypt(packet)
                unreliableSend(encodedPacket, serverSock, user, errRate)
                
                print("DATA: Server sends packet number {} now".format(sequenceNumber+1))
                
            # if client sends wrong packet
            if decideStatus(data[0]) == "INVALID CODE":
                print("ERROR: Client sent invalid packet type number")
                exit(1)
                

    # if socket timeouts catch the exception here
    except socket.timeout:
        if clientHasSessionKey == False and sessionKey is not None:
            SessionKeyTimeoutRetryTimes -= 1
            if SessionKeyTimeoutRetryTimes == 0:
                print("ERROR: Client did not notify Server about receiving the session key")
                exit(1)
            # prepare the packet
            length = toByte(len(sessionKey))
            pType = toByte(0)
            packet = pType + length + sessionKey
            # encode the packet with RSA
            encodedPacket = rsaEncryptor.encrypt(packet);
            unreliableSend(encodedPacket, serverSock, user, errRate)
            print("TIMEOUT: Session key is sent again to the client")
        else:
            # execute the following code if file is already requested
            # and the contents have been parsed into a list
            # this if condition is put to ignore exceptions
            # before a client is connected to the server
            # or during handshaking
            if len(fileList) > 0 and sessionKey is not None:
                DataTransferTimeoutRetryTimes -= 1
                if DataTransferTimeoutRetryTimes == 0:
                    print("ERROR: Client stopped responding")
                    exit(1)
                    
                # set nextPacket variable to a non-existant value in the list
                nextPacket = -1
                
                # find last succesfully transmitted packet index
                for i in range(len(transmittedPackets)):
                    if transmittedPackets[i] == False:
                        nextPacket = i
                        break
                
                # if all packets have been transmitted, server can terminate
                if nextPacket == -1:
                    print("INFO: Transmission completed")
                    exit(0)
                
                # GO-BACK-N method and boundary checking for index errors
                if nextPacket - N > 0:
                    nextPacket = nextPacket - N
                else:
                    nextPacket = 0
                    
                # resend the N packets again to client
                # also send the next packet that has not been transmitted yet
                # to continue the process
                for goBackAmount in range(N + 2):
                    # boundary checking for index errors
                    if goBackAmount == len(fileList):
                        break;
                    payload = fileList[nextPacket+goBackAmount]
                    packet = toByte(2) + toByte(len(payload)) + toByte(nextPacket+goBackAmount) + payload.encode()
                    packet = pad(packet)
                    encodedPacket = AEScipher.encrypt(packet)
                    unreliableSend(encodedPacket, serverSock, user, errRate)
                    
                    if goBackAmount == N + 1:
                        print("DATA: Server sends packet number {} now".format(nextPacket+goBackAmount))
                    else:
                        print("TIMEOUT: sent packet number {} again".format(nextPacket+goBackAmount))
        pass
