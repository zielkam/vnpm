#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed May 19 09:11:38 2021

@author: zielony
"""

from struct import unpack
import re

class DecompressedFrame(object):

    frame_type = "UDP"
    
    
    def __init__(self,src_port=None,dst_port=None,src_addr=None,dst_addr=None,udpcontent=None,ipv4fFrame=None):
        
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.udpcontent = udpcontent
        self.ipv4FullFrame = ipv4fFrame
        self.frame_type = 'UDP'
    
    def detect_frame_type(self):
        #try:
            frame=unpack('{}s'.format(len(self.udpcontent)),self.udpcontent)
            content=str(frame[0].decode('utf-8')).split('\r\n')[0]
            RRLine=content.split(" ")
            if "SIP/2.0" in RRLine:
                self.frame_type="SIP"
       # except:
       #     pass
        
    def set_frame_type(self,ftype):
        self.frame_type=ftype


class SDPheader(object):
    media_addr=None
    media_port=None
    media_codecslist=list()
    media_type="audio"
    
    def __init__(self):
        self.media_addr=None
        self.media_port=None
        self.media_codecslist=list()
        self.media_type="audio"
    pass
        
class SIPFrame(DecompressedFrame):
    
    method=""
    fromheader=""
    toheader=""
    callid=""
    media_content_len=""
    fullcontent=""
    SDP=list()
    
    def __init__(self,frame):
        self.__dict__.update(frame.__dict__)
        pass


    def parseSDP(self,SDPcontent):
        obj=SDPheader()
        
        for entry in SDPcontent.split("\r\n"):


            if re.match(r'c=IN',entry):
                obj.media_addr=entry.split("=")[1].split()[2]
            
            if re.match(r'm=audio',entry):
                obj.media_port=entry.split("=")[1].split()[1]
                for x in entry.split("=")[1].split()[3:]:
                    obj.media_codecslist.append(x)
            if obj not in self.SDP:
                self.SDP.append(obj)
        pass
        
      
    def tryDecodeSIP(self):

        try:
            frame=unpack('{}s'.format(len(self.udpcontent)),self.udpcontent)    
            self.fullcontent = str(frame[0].decode('utf-8')).split('\r\n') 
            RRLine=self.fullcontent[0].split(" ")
            if re.match(RRLine[0], "SIP/2.0",re.IGNORECASE):
                self.method=RRLine[1]
            else:
                self.method=RRLine[0]
    
            self.fromheader =[ line for line in self.fullcontent if re.match("^from: ",line,re.IGNORECASE)]
            self.toheader = [ line for line in self.fullcontent if re.match(r'^to:',line,re.IGNORECASE) ]
            self.callid = [ line for line in self.fullcontent if re.match(r'^call-id:',line,re.IGNORECASE) ]
            self.media_content_len = next(( int(line.split(':')[1]) for line in self.fullcontent  if re.match(r'Content-Length:',line,re.IGNORECASE) ),0 )
            self.media_content_type = next((line.split(':')[1]  for line in self.fullcontent   if re.match(r'Content-Type:',line,re.IGNORECASE)),"application/sdp")
    
            if self.media_content_len>0:
                media_content=unpack('{}s'.format(len(self.udpcontent[-self.media_content_len:])),self.udpcontent[-self.media_content_len:])
                sdpcontent=media_content[0].decode('utf-8')
                self.parseSDP(sdpcontent)
            
        except:
            pass

class RTPFrame(DecompressedFrame):
    
    media_codec="" # media codec
    sequence=0
    stream="" # bytes of audio
    
    def __init__(self,frame):
        self.__dict__.update(frame.__dict__)
        pass
