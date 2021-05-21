# -*- coding: utf-8 -*-

import socket
import time

def startCollector(framesQueue,interface):
    
    server=socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(3)) 
    server.bind((interface,0)) 
    i=0

    while True: 

        i+=1
        eth_frame,eth_iface=server.recvfrom(65535) 
        if i%10000==0:
            time.sleep(0.5)
            i=0
        timestamp=float(time.time())
        framesQueue.put([timestamp,eth_frame])
        

    
if __name__ == "__main__":
        print("Hi, start deamon")

    

        
