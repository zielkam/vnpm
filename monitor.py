#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May 13 15:37:17 2021

@author: zielony
"""
from libnet_monitor import startCollector
from libnet_monitor_parser import analyzeFrame
from multiprocessing import Queue,Process,Pool
import multiprocessing
import time
import os

import sqlite3
        
    

def viewStats(stamp,events):
    import datetime
            
    if stamp is not None and events is not None:
        os.system('cls||clear')
    
        print("godzina: ",datetime.datetime.fromtimestamp(stamp),"ilosc wiadomosci sip:" ,len(events),)
        mcount=dict()
    
        for entry in events:
            sip=entry[4][0].split(" ")
            if sip[0]== "SIP/2.0":
                method=sip[1]
            else:    
                method=sip[0]
        
            if method not in mcount:
                mcount[method]=0
            mcount[method]+=1
        print("metoda","ilosc zdarzen")
        for name,count in mcount.items():
            print (name,count)
    time.sleep(1)
        
def storeData(filename,events,):

    if len(events)>0:
        with sqlite3.connect(filename) as connection:
            cursor=connection.cursor()
            i=0
            if len(list(events.keys()[:-2]))>0:
                for stamp in list(events.keys()[:-2]):
                    i+=1 
                    if len(events[stamp])>0:
                        eventlist=events.pop(stamp)
                
                    for event in eventlist:
         
                        src,dst,sport,dport,sip=event
                        query="INSERT INTO sip_events (timestamp,source_addr,dest_addr,src_port,dest_port,headers) \
                                        values (?,?,?,?,?,?)"
                        cursor.execute(query,[stamp,src,dst,sport,dport,str(sip)])
                        
                    if i%1000 == 0:
                        connection.commit()
                        time.sleep(0.5)
                i=0

                  


def viewAndStore(proxyDict,sqlitefile):


    if os.path.exists(sqlitefile):
        os.remove(sqlitefile)
    with sqlite3.connect(sqlitefile) as connection:
        cursor=connection.cursor()
        
        cursor.execute('CREATE TABLE sip_events (timestamp text,source_addr text,dest_addr text,src_port text,\
                       dest_port text,headers text) ')
        connection.commit()
    
    time.sleep(1)

    latestevent=None
    lateststamp=None

    while True:
        
        if len(proxyDict) > 0:
            lateststamp=list(proxyDict.keys())[-1]
            latestevent=proxyDict[lateststamp]


        #try:
        dbStore=Process(target=storeData,args=(sqlitefile,proxyDict,))
        view=Process(target=viewStats,args=(lateststamp,latestevent,))
        
        view.start()
        dbStore.start()
        view.join()
        dbStore.join()

def storeFrame():
    #bytes to database
    return 0

def retrieveRTPMonitored():
    # from database
    return 0
          
def AnalyzerThreads(number,framesQueue,newdict,localmanager,SIGPORTS):
    
    
    processPool=Pool(processes=number)
    timer=0
    objectsToMonitor=retrieveRTPMonitored()
    while True:

        try:
            timestamp,frame = framesQueue.get(block=False)
            timer+=1
        except:
            frame=None
            time.sleep(0.1)
            pass
        
        if frame:
            searchSIG=processPool.apply_async(analyzeFrame,(frame,SIGPORTS))
            
        
            sigFrame=searchSIG.get()

            if sigFrame is not None:
                if int(timestamp) not in newdict:
                    listprototype = localmanager.list()
                    newdict[int(timestamp)]= listprototype
                newdict[int(timestamp)].append(sigFrame)
    
        if timer%1000==0:
            time.sleep(0.1)
            timer=0



    processPool.close()

def main(cfg):
    
    # LIVE CONFIGURATION - WHAT TO RECORD
    extras=retrieveRTPMonitored()
    
    mmanage = multiprocessing.Manager()
    statsDict = mmanage.dict()

    framesQueue=Queue()

    collectorProc=Process(target=startCollector, args=(framesQueue,cfg['general']['interface']))
    collectorProc.daemon=True
    collectorProc.start()
    print("[",collectorProc.pid,"] Started main thread")
    time.sleep(3)
 
    viewStoreProc=Process(target=viewAndStore, args=(statsDict,cfg['dbconf']['dbfile'],))

    parsersProc=Process(target=AnalyzerThreads,args=(cfg['general']['num_of_processes'],framesQueue,statsDict,mmanage,cfg['monitor']['ports']))
    parsersProc.deamon=True
    parsersProc.start()
    print("[",parsersProc.pid,"] Started frame parsers")
    viewStoreProc.start()
    print("[",viewStoreProc.pid,"] Started live view stats and dbcollector") 
    
    parsersProc.join()
    viewStoreProc.join()

def yaml_parsecfg(configFile):
    
    import yaml
    with open(configFile,'r') as conf:
        cfg = yaml.safe_load(conf)
        

    if "general" not in cfg.keys():
        raise Exception("Brak  sekcji general w server.yml") 

    return cfg


if __name__ == "__main__":
    
# TASK CONFIUGRATION
    configuration=yaml_parsecfg("./server.yml")


# RUN MAIN :)
    main(configuration)