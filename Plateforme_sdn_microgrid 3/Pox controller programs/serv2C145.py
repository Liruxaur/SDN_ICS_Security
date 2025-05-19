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

def server(nomhote, port):
    global ref
    global packetreceived
    main_connexion = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    unpackerConsigne = struct.Struct('f')
    unpacker = struct.Struct('f f')

    """Connection handling"""
    server_address = (nomhote, port)
    main_connexion.bind(server_address)
    print('\nstarting up on %s port %s' %server_address)
    main_connexion.listen(5)
    server_online = True
    list_clients_co = []
    while server_online:
        connexions_demandees, wlist, xlist = select.select([main_connexion], [], [], 1)
        for connexion in connexions_demandees:
            connexion_client, infos_client = connexion.accept()
            print("\nNew connection with client : {}".format(infos_client))
            list_clients_co.append(connexion_client)

        clients_to_read = []
        try:
            client_to_read, wlist, xlist = select.select(list_clients_co, [], [], 0.05)
                #print(client_to_read)
        except select.error:
            pass
        else:
            for i,client in enumerate(client_to_read):
                msg_recu = client.recv(unpackerConsigne.size)
                packetreceived = msg_recu
                unpacked = unpackerConsigne.unpack(msg_recu)
                print("Instruction Received : {}".format(unpacked[0]))
                with refresh:
                    consigne = unpacked[0] #getting the instruction
                    senddataArduino(consigne) #sending the instruction to the Arduino
                    refresh.notifyAll()
    print("Connection closed")
    for client in list_clients_co:
        client.close()
    main_connexion.close()


def client(hote, port, skip_sending=False):
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
            #waiting for notification
            with refresh:
                refresh.wait()
                unpacked = unpackerConsigne.unpack(packetreceived)
                consigne = unpacked[0]
                time.sleep(3) #failsafe 
                if (ser.inWaiting() > 0): #if something in the buffer not necessary
                    mesure = ser.readline()[:-2]
                #mesure = ser.read(4)

                msgToSend = (consigne, float(mesure)) #tuple with the instruction and the measure

                print(msgToSend)
                PackedmsgTosend = unpacker.pack(*msgToSend) #building the packet
                timestamp_when_sent = time.time()
                if not skip_sending: 
                  connexionServer.send(PackedmsgTosend)
                  print("Timestamp when sent:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_when_sent)))
                ack = connexionServer.recv(1024)  # Adjust the buffer size as needed
                timestamp_ack_received = time.time() 
                                
                if ack == b"ACK":
                    print("ACK received")
                    print("Timestamp when ACK received:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_ack_received)))
                    ack_timestamps[hote] = timestamp_ack_received  # Save the ACK timestamp for this host
                    print("Ack Timestamps:", ack_timestamps)                    
                                  
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
client1 = Thread(target = client, args=('192.168.1.103', 12800, False))
client2 = Thread(target = client, args=('192.168.1.151', 12800, False))
client3 = Thread(target = client, args=('192.168.1.144', 12800, True))
client2.start()
client1.start()
client3.start()
server.start() 
