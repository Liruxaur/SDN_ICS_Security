from threading import Thread, RLock, Condition
import socket
import select
import struct
import binascii
import serial
import time

ser = serial.Serial("/dev/ttyACM0", 9600, timeout = 1)
#ser.flushInput()
ref = 0
refresh = Condition()
packetreceived = 0
mesure = 0 #global because if several clients, there will always one value written in the serial buffer as soon the first client reads it the buffer is empty and no other measure is to be writter so the other clients have no measure to get : they crash

def send_acknowledgment(client_socket):
    # Send an ACK message to the client
    ack_message = b"ACK"
    client_socket.send(ack_message)
    

def server(nomhote, port):
    global ref
    global packetreceived
    main_connexion = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    unpackerConsigne = struct.Struct('f')
    unpacker = struct.Struct('f f')

    """Connection handling"""
    server_address = (nomhote, port)
    main_connexion.bind(server_address)
    print('\nstarting up on %s port %s' % server_address)
    main_connexion.listen(5)
    server_online = True
    client_sockets = {}  # Dictionary to store client sockets and their IP addresses

    while server_online:
        connexions_demandees, wlist, xlist = select.select([main_connexion], [], [], 1)
        for connexion in connexions_demandees:
            connexion_client, infos_client = connexion.accept()
            client_ip = infos_client[0]  # Get the client's IP address
            print("\nNew connection with client : {}".format(infos_client))
            client_sockets[client_ip] = connexion_client

        clients_to_read = []
        try:
            client_to_read, wlist, xlist = select.select(list(client_sockets.values()), [], [], 0.05)
        except select.error:
            pass
        else:
            for client in client_to_read:
                msg_recu = client.recv(unpackerConsigne.size)
                packetreceived = msg_recu
                unpacked = unpackerConsigne.unpack(msg_recu)
                print("Instruction Received : {}".format(unpacked[0]))

                # Send an ACK to client "192.168.1.145"
                if "192.168.1.145" in client_sockets and client_sockets["192.168.1.145"] == client:
                    send_acknowledgment(client)

                with refresh:
                    consigne = unpacked[0]  # Getting the instruction
                    senddataArduino(consigne)  # Sending the instruction to the Arduino
                    refresh.notifyAll()

    print("Connection closed")
    for client in client_sockets.values():
        client.close()
    main_connexion.close()


def client(hote, port):
    global ref
    global ser
    global packetreceived
    global mesure
    unpackerConsigne = struct.Struct('f')
    unpacker = struct.Struct('f f')

    connexionServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connexionServer.connect((hote, port))
    print("\nConnection established with the server on port : {}".format(port))

    client_is_co = True
    new_msg = ""

    while client_is_co:
        if new_msg != "fin":
            #envoi du message
            with refresh:
                refresh.wait()
                unpacked = unpacker.unpack(packetreceived)
                consigne = unpacked[0]
                time.sleep(3) #failsafe 
                if (ser.inWaiting() > 0): #if something in the buffer not necessary
                    mesure = ser.readline()[:-2]
                #mesure = ser.read(4)

                msgToSend = (consigne, float(mesure)) #tuple with the instruction and the measure

                #print(msgToSend)
                PackedmsgTosend = unpacker.pack(*msgToSend) #building the packet
                connexionServer.send(PackedmsgTosend)
        else:
            connexionServer.send(b"shutdown")
            client_is_co = False


    #fermeture
    print("\nConnection closed")
    connexionServer.close()

def senddataArduino(data):
    global ser
    instructionToSend = b"%f" %data
    ser.write(instructionToSend)

server = Thread(target = server, args=('', 12800))
client1 = Thread(target = client, args=('192.168.1.144', 12800))

server.start()
client1.start()
