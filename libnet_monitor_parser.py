#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri May 21 16:02:07 2021

@author: zielony
"""
from struct import unpack
from socket import inet_ntoa

from framesModels import DecompressedFrame,SIPFrame

def l2decompress(frame):
    # According to documentation first 14 bytes are l2 header, macs, seq etc, not interesting
    data=frame[:14]
    return data

def l3decompress(frame):
    # 20 bytes of frame is l2, adresses, ttl, protocols etc
    ipv4data=frame[14:]
    vihl,dscpecn,hlen,iden,ff,ttl,protocol,hc,saddr,daddr = unpack('!BBHHHBBH4s4s' ,ipv4data[0:20])
    saddr,daddr=inet_ntoa(saddr),inet_ntoa(daddr)
    udpheaderlen=(vihl & 0xF ) * 4

    udpdata=ipv4data[udpheaderlen:]
    
    
    # retrieve ports etc
    try:
        srcport,dstport,udplen,checksum=unpack("!HHHH",udpdata[0:8])
    except:
        srcport=0
        dstport=0
        pass

    # retrieve message content
    content=ipv4data[(vihl & 0XF)*4+8:] 
    return DecompressedFrame(src_addr=saddr,dst_addr=daddr,src_port=srcport,dst_port=dstport,udpcontent=content,ipv4fFrame=ipv4data)
   # return saddr,daddr,srcport,dstport,content,ipv4data


def analyzeFrame(frame,ports=['5060','5061','5062']):

    if frame != "ANALYZE":
        l2d=l2decompress(frame)
    
        dframe=l3decompress(frame)
        
        if  (dframe.dst_port or dframe.src_port) in  ports:
            dframe.detect_frame_type()
            if dframe.frame_type=="SIP":
                sipmessage = SIPFrame(dframe)
                sipmessage.tryDecodeSIP()
                return (sipmessage.src_addr,sipmessage.dst_addr,sipmessage.src_port,sipmessage.dst_port,sipmessage.fullcontent)
            else:
                return None
        else:
            # i tu będzie RTP, trzeba wystartować proces, zapisać dialog który proces zainicjował na listę przy każdym SIPframe patrzeć czy dialog się zakończył, względnie
            # wystartować timer, który zamknie zbieracza po 10 sekundach (ze względu na opóźnienia w sieci), timer konfigurowalny
            return None

        