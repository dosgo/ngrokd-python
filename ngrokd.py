import socket
import ssl
import threading
import sys
import logging
import subprocess
import json
import os
import struct
import random
import select
import time


#config
Ver="0.3-(2016-01-14)"
SERVERDOMAIN = "yuancheng.kos.org.cn"  
SERVERHTTP=90
SERVERHTTPS=444
SERVERPORT=4443

keyfile='domain.key'
certfile='server.crt'



class NgrokdPython(object):

    def __init__(self, window=None):
        self.proxylist={}  #http or https
        self.tcplist={} #tcp
        self.reglist={}
        self.SUBDOMAINS={}
        self.HOSTS={}
        self.TCPS={}
        self.Atokens = []
        self.ATOKEN=False
        self.tcpsocks=[]
        self.tcpsockinfos={}
        self.ClientIds={}





    def httphead(self,request):
        http = request.split("\n")
        REQUEST_METHOD = http[0][0:http[0].find(' ')]
        back = {}
        for line in http:
            pos=line.find(':')
            if pos!=-1:
                key=line[0:pos]
                value=line[int(pos)+1:]
                back[key] = value.strip()
                back["REQUEST_METHOD"] = REQUEST_METHOD
        if back.has_key('Host'):
            if back['Host'].find('.')!=-1:
                DOMAIN=back['Host'][:back['Host'].find('.')]
                back["SUBDOMAIN"] =DOMAIN
            if back['Host'].find(':')!=-1:
                DOMAIN=back['Host'][:back['Host'].find(':')]
                back["DOMAIN"] =DOMAIN
            if back['Host'].find(':')!=-1:
                back["Host"] =back['Host'][:back['Host'].find(':')]

        return back


    def tcp_server(self):

        outputs=[]
        while True:
            #try:
            if len(self.tcpsocks)<1:
                time.sleep(0.1)
            if len(self.tcpsocks)>0:
                readable,writeable,exceptional = select.select(self.tcpsocks,outputs,[])
                if len(readable)>0:
                    for i in range(0,len(self.tcpsocks)):
                        #good 
                        if(i>len(self.tcpsocks)-1):
                            break;

                        if self.tcpsocks[i] in readable:
                            #new connect
                            if  self.TCPS.has_key(self.tcpsocks[i]):
                                ClientId=self.TCPS[self.tcpsocks[i]]['ClientId']
                                PORT=self.TCPS[self.tcpsocks[i]]['RemotePort']
                                Csock=self.TCPS[self.tcpsocks[i]]['Csock']
                                client,addr=self.tcpsocks[i].accept()
                                client.setblocking(0)
                                client.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 0)  
                                sockinfo={}
                                sockinfo['ClientId']=ClientId
                                sockinfo['PORT']=PORT
                                self.tcpsockinfos[client]=sockinfo
                                self.tcpsocks.append(client)
                                dict = {} 
                                dict["Type"]="ReqProxy"
                                dict["Payload"]={}
                                self.sendpack(Csock,dict)
                                continue
                            else:
                                try:
                                    data = self.tcpsocks[i].recv(9216)
                                    if self.tcplist.has_key(self.tcpsocks[i]):
                                        self.send(self.tcplist[self.tcpsocks[i]],data)
                                        continue

                                    if self.tcpsockinfos.has_key(self.tcpsocks[i]):
                                        ClientId=self.tcpsockinfos[self.tcpsocks[i]]['ClientId']
                                        PORT=self.tcpsockinfos[self.tcpsocks[i]]['PORT']

                                    if self.reglist.has_key(ClientId):
                                        regitem=self.reglist[ClientId]
                                    else:
                                        regitem=[]
                                    reginfo={}
                                    reginfo['Protocol']='tcp'
                                    reginfo['Subdomain']=''
                                    reginfo['rsock']= self.tcpsocks[i]
                                    reginfo['rport']=PORT
                                    reginfo['buf']= data
                                    regitem.append(reginfo)
                                    self.reglist[ClientId]=regitem
                                except Exception,e:
                                    print("error9\r\n");
                                    print e
                                    if e.errno!=9:
                                        self.tcpsocks[i].shutdown(socket.SHUT_RDWR)
                                        self.tcpsocks[i].close()
                                    self.tcpsocks.remove(self.tcpsocks[i])



    def http_server(self,httpsock,Protocol):
        inputs=[httpsock]
        outputs=[]
        while True:
            #try:
            readable,writeable,exceptional = select.select(inputs,outputs,inputs)
            if len(readable)>0:
                for i in range(0,len(inputs)):
                    #good 
                    if(i>len(inputs)-1):
                        break;

                    if inputs[i] in readable:
                        #new connect
                        if inputs[i]==httpsock:
                            client,addr=httpsock.accept()
                            print("http new sock\r\n")
                            try:
                                client.setblocking(0)
                                client.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 0)  
                            except Exception,e:
                                print("error5")
                                print e
                            inputs.append(client)
                            continue
                        else:
                            try:
                                data = inputs[i].recv(9216)
                                print (data)
                                heads=self.httphead(data)
                                if  self.proxylist.has_key(inputs[i]):
                                    print("ddd1\r\n");
                                    self.send(self.proxylist[inputs[i]],data);
                                    continue
                                if heads.has_key("Host"):
                                    print("ddd\r\n");
                                    if self.HOSTS.has_key(heads['Host']):
                                        print("ddd10\r\n");
                                        dict = {} 
                                        dict["Type"]="ReqProxy"
                                        dict["Payload"]={}
                                        back=self.sendpack(self.HOSTS[heads['Host']]['sock'],dict)
                                        if self.reglist.has_key(self.HOSTS[heads['Host']]['clientid']):
                                            regitem=self.reglist[self.HOSTS[heads['Host']]['clientid']]
                                        else:
                                            regitem=[]
                                        print("ddd11\r\n");
                                        reginfo={}
                                        reginfo['Protocol']=Protocol
                                        reginfo['Host']=heads['Host']
                                        reginfo['rsock']= inputs[i]
                                        reginfo['buf']= data
                                        regitem.append(reginfo)
                                        self.reglist[self.HOSTS[heads['Host']]['clientid']]=regitem
                                        print("ddd12\r\n");
                                    else:
                                        self.show404(inputs[i])
                                        inputs.remove(inputs[i])
                                else:
                                    self.show404(inputs[i])
                                    inputs.remove(inputs[i])


                            except Exception,e:
                                print("error\r\n");
                                print e
                                if inputs[i]!=httpsock and e.errno!=9:
                                    inputs[i].shutdown(socket.SHUT_RDWR)
                                    inputs[i].close()
                                inputs.remove(inputs[i])
            #except socket.error,e:
            #    print("error1\r\n");
            #    print e
            #    break

            
    def https_thread(self):
        httpsock = ssl.wrap_socket(socket.socket(),keyfile,certfile,  True)
        httpsock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
        httpsock.bind( ('0.0.0.0', SERVERHTTPS) )
        httpsock.listen(500)
        httpsock.setblocking(0)
        httpsock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 0)  
        self.http_server(httpsock,'https')

    def http_thread(self):
        httpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        httpsock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
        httpsock.bind( ('0.0.0.0', SERVERHTTP) )
        httpsock.listen(500)
        httpsock.setblocking(0)
        httpsock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 0)  
        self.http_server(httpsock,'http')

    def server_thread(self):
        sock = ssl.wrap_socket(socket.socket(),keyfile,certfile,server_side=True,cert_reqs=ssl.CERT_NONE)
        sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
        sock.bind( ('0.0.0.0', SERVERPORT) )
        sock.listen(100)
        sock.setblocking(0)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 0)  
        inputs=[sock]
        outputs=[]
        tosocklist={}
        hostsock={}
        while True:
                try:
                    readable,writeable,exceptional = select.select(inputs,outputs,inputs)
                except socket.error,e:
                    print("select error")
                if len(readable)>0:
                    try:
                        for i in range(0,len(inputs)):
                            #good 
                            if(i>len(inputs)-1):
                                break;
                            if inputs[i] in readable:
                                #new connect
                                if inputs[i]==sock:
                                    client,addr=sock.accept()
                                    client.setblocking(0)
                                    inputs.append(client)
                                    continue
                                if inputs[i]!=sock:
                                    data = inputs[i].recv(4096)
                                    #print(data)
                                    if  tosocklist.has_key(inputs[i])  and  len(data)>0:
                                        self.send(tosocklist[inputs[i]],data);
                                        continue

                                   
                                    if not data:
                                        if tosocklist.has_key(inputs[i]):
                                            tosocklist[inputs[i]].shutdown(socket.SHUT_RDWR)
                                            tosocklist.pop(inputs[i])
                                    if len(data)>=4:                                   
                                        lenbyte=struct.unpack("i", data[0:4])
                                        if len(data)==(lenbyte[0]+8):
                                            js=json.loads(data[8:])
                                            if js["Type"]=="Auth":
                                                dict = {} 
                                                dict["Type"]="AuthResp";
                                                dict["Payload"]={};
                                                dict["Payload"]["Version"]=js["Payload"]["Version"]
                                                dict["Payload"]["MmVersion"]=js["Payload"]["MmVersion"]
                                                #atokens error
                                                if self.ATOKEN and js["Payload"]["User"] not  in self.Atokens:
                                                    dict["Payload"]["Error"]="access denied"
                                                    inputs[i].setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 0)  
                                                    self.sendpack(inputs[i],dict)
                                                    #inputs[i].shutdown(socket.SHUT_RDWR)
                                                    #inputs[i].close()
                                                    inputs.remove(inputs[i])
                                                    continue


                                                if js["Payload"]["ClientId"]=='':
                                                    js["Payload"]["ClientId"]=''.join(random.sample('zyxwvutsrqponmlkjihgfedcba',10))
                                                dict["Payload"]["ClientId"]= js["Payload"]["ClientId"]
                                                ClientId=dict["Payload"]["ClientId"]
                                                self.ClientIds[inputs[i]]=ClientId
                                                dict["Payload"]["Error"]=""
                                                self.sendpack(inputs[i],dict)
                                            if js["Type"]=="Ping":
                                                dict = {} 
                                                dict["Type"]="Pong";
                                                self.sendpack(inputs[i],dict)
                                            if js["Type"]=="ReqTunnel":
                                                if js["Payload"]["Protocol"]=="http" or js["Payload"]["Protocol"]=="https":
                                                    dict = {} 
                                                    dict["Type"]="NewTunnel";
                                                    dict["Payload"]={};
                                                    dict["Payload"]["ReqId"]=js["Payload"]["ReqId"]
                                                    dict["Payload"]["Protocol"]=js["Payload"]["Protocol"]

                                                    if js["Payload"].has_key("Hostname") and len(js["Payload"]['Hostname'])>0:
                                                        dict["Payload"]["Hostname"]=js["Payload"]['Hostname']
                                                    else:
                                                        if js["Payload"]["Subdomain"]=='':
                                                            js["Payload"]["Subdomain"]=''.join(random.sample('zyxwvutsrqponmlkjihgfedcba',5))
                                                        dict["Payload"]["Hostname"]=js["Payload"]["Subdomain"]+'.'+SERVERDOMAIN

                                                        
                                                    if js["Payload"]["Protocol"]=="http" and  SERVERHTTP!=80:
                                                        dict["Payload"]["Url"]=js["Payload"]["Protocol"]+"://"+dict["Payload"]["Hostname"]+":"+str(SERVERHTTP)
                                                    elif js["Payload"]["Protocol"]=="https" and  SERVERHTTPS!=443:
                                                        dict["Payload"]["Url"]=js["Payload"]["Protocol"]+"://"+dict["Payload"]["Hostname"]+":"+str(SERVERHTTPS)
                                                    else:
                                                        dict["Payload"]["Url"]=js["Payload"]["Protocol"]+"://"+dict["Payload"]["Hostname"]
                                                       
                                                    
                                                    SUBDOMAININFO={}
                                                    SUBDOMAININFO["sock"]=inputs[i];
                                                    if self.ClientIds.has_key(inputs[i]):
                                                        SUBDOMAININFO["clientid"]=self.ClientIds[inputs[i]];
                                                    dict["Payload"]["Error"]=""
                                                    if self.HOSTS.has_key(dict["Payload"]["Hostname"]):
                                                        dict["Payload"]["Error"]="The tunnel "+js["Payload"]["Protocol"]+"://"+dict["Payload"]["Hostname"]+" is already registered."
                                                    self.HOSTS[dict["Payload"]["Hostname"]]=SUBDOMAININFO
                                                    hostsock[inputs[i]]=dict["Payload"]["Hostname"]
                                                    self.sendpack(inputs[i],dict)
                                                if js["Payload"]["Protocol"]=="tcp":
                                                    dict={}
                                                    dict["Payload"]={}
                                                    dict["Payload"]["Error"]=""
                                                    try:
                                                        tcpsock =socket.socket()
                                                        tcpsock.bind( ('0.0.0.0', int(js["Payload"]["RemotePort"])) )
                                                        tcpsock.listen(500)
                                                        self.tcpsocks.append(tcpsock);
                                                        sockinfo=tcpsock.getsockname();
                                                        tcpsock.setblocking(0)
                                                        tcpsock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 0)  
                                                        dict["Payload"]["Url"]="tcp://"+SERVERDOMAIN+':'+str(sockinfo[1])
                                                    except Exception,e:
                                                        dict["Payload"]["Error"]="Bind error"
                                                    dict["Type"]="NewTunnel";
                                                    dict["Payload"]["ReqId"]=js["Payload"]["ReqId"]
                                                    dict["Payload"]["Protocol"]='tcp'
                                                    self.sendpack(inputs[i],dict)
                                                    TCPINFO={}
                                                    TCPINFO['Csock']=inputs[i];
                                                    TCPINFO['RemotePort']=js["Payload"]["RemotePort"]
                                                    if self.ClientIds.has_key(inputs[i]):
                                                        TCPINFO['ClientId']=self.ClientIds[inputs[i]];
                                                    self.TCPS[tcpsock]=TCPINFO;




                                            if  js["Type"]=="RegProxy":
                                                if self.reglist.has_key(js["Payload"]["ClientId"]):
                                                    if len(self.reglist[js["Payload"]["ClientId"]])>0:
                                                        linkinfo=self.reglist[js["Payload"]["ClientId"]].pop()
                                                        if(linkinfo['Protocol']=='http' or linkinfo['Protocol']=='https'):
                                                            tosock=linkinfo['rsock']
                                                            tosocklist[inputs[i]]=tosock
                                                            sockinfo=tosock.getpeername();
                                                            dict = {} 
                                                            dict["Type"]="StartProxy";
                                                            dict["Payload"]={};
                                                            dict["Payload"]['Url']=linkinfo['Protocol']+'://'+linkinfo['Host']
                                                            dict['Payload']['ClientAddr']=str(sockinfo[0])+':'+str(sockinfo[1]);#ip +port
                                                            self.sendpack(inputs[i],dict)
                                                            self.send(inputs[i],linkinfo['buf'])
                                                            self.proxylist[tosock]=inputs[i]

                                                        if linkinfo['Protocol']=='tcp':
                                                            tosock=linkinfo['rsock']
                                                            tosocklist[inputs[i]]=tosock
                                                            sockinfo=tosock.getpeername();
                                                            dict = {} 
                                                            dict["Type"]="StartProxy";
                                                            dict["Payload"]={};
                                                            dict["Payload"]['Url']=linkinfo['Protocol']+'://'+SERVERDOMAIN+':'+str(linkinfo['rport'])
                                                            dict['Payload']['ClientAddr']=str(sockinfo[0])+':'+str(sockinfo[1]);#ip +port
                                                            self.sendpack(inputs[i],dict)
                                                            self.send(inputs[i],linkinfo['buf'])
                                                            self.tcplist[tosock]=inputs[i]


                    except socket.error,e:
                        print "error10"
                        print e
                        if  hostsock.has_key(inputs[i]):
                            if self.HOSTS.has_key(hostsock[inputs[i]]):
                                self.HOSTS.pop(hostsock[inputs[i]])
                        try:
                            inputs[i].shutdown(socket.SHUT_RDWR)
                        except socket.error:
                            print "ddd3"
                        if inputs[i] !=sock:
                            inputs.remove(inputs[i])
                        






    def show404(self,sock):
        body = 'Tunnel not found.'
        request = 'HTTP/1.0 404  '+"\r\n"+' 404 Not Found.' + "\r\n" + 'Content-Length: ' + chr(len(body)) +"\r\n\r\n" + body
        sock.setblocking(1)
        sock.send(request)
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()


    def main_thread(self):
    #read config
        if os.path.exists('atoken'):
            fd = file( "atoken", "r" )
            for line in fd.readlines():
                self.Atokens.append(line.strip('\n').strip('\r'))


    #start http
        self.httpt = threading.Thread(target = self.http_thread, args = () )
        self.httpt.start()

    #start https
        self.httpst = threading.Thread(target = self.https_thread, args = () )
        self.httpst.start()
    #tcp server
        self.tcpt = threading.Thread(target = self.tcp_server, args = ())
        self.tcpt.start()

    #start server
        self.servert = threading.Thread(target = self.server_thread, args = () )
        self.servert.start()


    def send(self,client,buf):
        client.setblocking(1)
        sendlen=client.send(buf);
        client.setblocking(0)
        return sendlen

    def sendpack(self,client,dict):
        client.setblocking(1)
        jsonstr=json.dumps(dict)
        len1=struct.pack("i",len(jsonstr))
        len2=struct.pack("i",0)
        sendlen=client.send(len1+len2+jsonstr);
        client.setblocking(0)
        return sendlen



def run():
    print "ngrokd-python v"+str(Ver)+"\r\n"
    ngrokdpy = NgrokdPython()
    ngrokdpy.main_thread()

run();