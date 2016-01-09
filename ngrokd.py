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


#config
Ver="0.1-(2016-01-09)"
SERVERDOMAIN = "16116.org"  
SERVERHTTP=90
SERVERHTTPS=444
SERVERPORT=4443



class NgrokdPython(object):

    def __init__(self, window=None):
        self.proxylist={}  #http or https
        self.tcplist={} #tcp
        self.reglist={}
        self.SUBDOMAINS={}
        self.HOSTS={}
        self.Atokens = []
        self.ATOKEN=False





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


    def tcp_server(self,csock,PORT,ReqId,ClientId):
        bind=True
        dict={}
        dict["Payload"]={}
        dict["Payload"]["Error"]=""
        try:
            tcpsock =socket.socket()
            tcpsock.bind( ('0.0.0.0', int(PORT)) )
            tcpsock.listen(500)
            inputs=[tcpsock]
            outputs=[]
            sockinfo=tcpsock.getsockname();
            tcpsock.setblocking(1)
        except Exception,e:
            dict["Payload"]["Error"]="Bind error"
            print e
            bind=False

        dict["Type"]="NewTunnel";
        dict["Payload"]["ReqId"]=ReqId
        dict["Payload"]["Protocol"]='tcp'
        if bind==True:
            dict["Payload"]["Url"]="tcp://"+SERVERDOMAIN+':'+str(sockinfo[1])
        self.sendpack(csock,dict)
        if bind==False:
            return False

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
                        if inputs[i]==tcpsock:
                            client,addr=tcpsock.accept()
                            client.setblocking(1)
                            inputs.append(client)
                            dict = {} 
                            dict["Type"]="ReqProxy"
                            dict["Payload"]={}
                            self.sendpack(csock,dict)
                            continue
                        if inputs[i]!=tcpsock:
                            try:
                                data = inputs[i].recv(9216)
                                if self.tcplist.has_key(inputs[i]):
                                    self.tcplist[inputs[i]].send(data)
                                    continue

                                if self.reglist.has_key(ClientId):
                                    regitem=self.reglist[ClientId]
                                else:
                                    regitem=[]
                                reginfo={}
                                reginfo['Protocol']='tcp'
                                reginfo['Subdomain']=''
                                reginfo['rsock']= inputs[i]
                                reginfo['rport']=PORT
                                reginfo['buf']= data
                                regitem.append(reginfo)
                                self.reglist[ClientId]=regitem
                            except Exception,e:
                                print("error\r\n");
                                if e.errno!=9:
                                    inputs[i].shutdown(socket.SHUT_RDWR)
                                    inputs[i].close()
                                inputs.remove(inputs[i])



    def http_server(self,httpsock,Protocol):
        inputs=[httpsock]
        outputs=[]
        while True:
            #try:
            readable,writeable,exceptional = select.select(inputs,outputs,inputs)
            print(len(inputs))
            if len(readable)>0:
                for i in range(0,len(inputs)):
                    #good 
                    if(i>len(inputs)-1):
                        break;

                    if inputs[i] in readable:
                        #new connect
                        if inputs[i]==httpsock:
                            client,addr=httpsock.accept()
                            client.setblocking(1)
                            inputs.append(client)
                            continue
                        if inputs[i]!=httpsock:
                            try:
                                data = inputs[i].recv(9216)
                                heads=self.httphead(data)
                                if  self.proxylist.has_key(inputs[i]):
                                    self.proxylist[inputs[i]].send(data)
                                    continue
                                if heads.has_key("Host"):
                                    if self.HOSTS.has_key(heads['Host']):
                                        dict = {} 
                                        dict["Type"]="ReqProxy"
                                        dict["Payload"]={}
                                        back=self.sendpack(self.HOSTS[heads['Host']]['sock'],dict)
                                        if self.reglist.has_key(self.HOSTS[heads['Host']]['clientid']):
                                            regitem=self.reglist[self.HOSTS[heads['Host']]['clientid']]
                                        else:
                                            regitem=[]
                                        reginfo={}
                                        reginfo['Protocol']=Protocol
                                        reginfo['Host']=heads['Host']
                                        reginfo['rsock']= inputs[i]
                                        reginfo['buf']= data
                                        regitem.append(reginfo)
                                        self.reglist[self.HOSTS[heads['Host']]['clientid']]=regitem
                                    else:
                                        self.show404(inputs[i])
                                        inputs.remove(inputs[i])
                                else:
                                    self.show404(inputs[i])
                                    inputs.remove(inputs[i])


                            except Exception,e:
                                print("error\r\n");
                                if e.errno!=9:
                                    inputs[i].shutdown(socket.SHUT_RDWR)
                                    inputs[i].close()
                                inputs.remove(inputs[i])
            #except socket.error,e:
            #    print("error1\r\n");
            #    print e
                #break

            
    def https_thread(self):
        httpsock = ssl.wrap_socket(socket.socket(),'domain.key', 'server.crt',  True)
        httpsock.bind( ('0.0.0.0', SERVERHTTPS) )
        httpsock.listen(500)
        httpsock.setblocking(1)
        self.http_server(httpsock,'https')

    def http_thread(self):
        httpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        httpsock.bind( ('0.0.0.0', SERVERHTTP) )
        httpsock.listen(500)
        httpsock.setblocking(1)
        self.http_server(httpsock,'http')

    def server_thread(self):
        sock = ssl.wrap_socket(socket.socket(),keyfile="domain.key",certfile="server.crt",server_side=True,cert_reqs=ssl.CERT_NONE)
        sock.bind( ('0.0.0.0', SERVERPORT) )
        sock.listen(100)
        sock.setblocking(1)
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
                                    client.setblocking(1)
                                    inputs.append(client)
                                    continue
                                if inputs[i]!=sock:
                                    data = inputs[i].recv(4096)
                                    #print(data)
                                    if  tosocklist.has_key(inputs[i])  and  len(data)>0:
                                        tosocklist[inputs[i]].send(data)
                                        continue

                                   
                                    if not data:
                                        if tosocklist.has_key(inputs[i]):
                                            tosocklist[inputs[i]].shutdown(socket.SHUT_RDWR)
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
                                                if ATOKEN and js["Payload"]["User"] not  in self.Atokens:
                                                    dict["Payload"]["Error"]="access denied"
                                                    inputs[i].setblocking(0)
                                                    inputs[i].setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 0)  
                                                    self.sendpack(inputs[i],dict)
                                                    inputs[i].setblocking(1)
                                                    #inputs[i].shutdown(socket.SHUT_RDWR)
                                                    #inputs[i].close()
                                                    inputs.remove(inputs[i])
                                                    continue


                                                if js["Payload"]["ClientId"]=='':
                                                    js["Payload"]["ClientId"]=''.join(random.sample('zyxwvutsrqponmlkjihgfedcba',10))
                                                dict["Payload"]["ClientId"]= js["Payload"]["ClientId"]
                                                ClientId=dict["Payload"]["ClientId"]
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
                                                    SUBDOMAININFO["clientid"]=ClientId;
                                                    dict["Payload"]["Error"]=""
                                                    if self.HOSTS.has_key(dict["Payload"]["Hostname"]):
                                                        dict["Payload"]["Error"]="The tunnel "+js["Payload"]["Protocol"]+"://"+dict["Payload"]["Hostname"]+" is already registered."
                                                    self.HOSTS[dict["Payload"]["Hostname"]]=SUBDOMAININFO
                                                    hostsock[inputs[i]]=dict["Payload"]["Hostname"]
                                                    self.sendpack(inputs[i],dict)
                                                if js["Payload"]["Protocol"]=="tcp":
                                                    tcpt = threading.Thread(target = self.tcp_server, args = (inputs[i],js["Payload"]["RemotePort"],js["Payload"]["ReqId"],ClientId))
                                                    tcpt.start()


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
                                                            inputs[i].send(linkinfo['buf'])
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
                                                            inputs[i].send(linkinfo['buf'])
                                                            self.tcplist[tosock]=inputs[i]


                    except socket.error,e:
                        if  hostsock.has_key(inputs[i]):
                            if self.HOSTS.has_key(hostsock[inputs[i]]):
                                self.HOSTS.pop(hostsock[inputs[i]])
                                continue
                        try:
                            inputs[i].shutdown(socket.SHUT_RDWR)
                            inputs.remove(inputs[i])
                        except socket.error:
                            print "ddd"
                        






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

    #start server
        self.servert = threading.Thread(target = self.server_thread, args = () )
        self.servert.start()



    def sendpack(self,client,dict):
        jsonstr=json.dumps(dict)
        len1=struct.pack("i",len(jsonstr))
        len2=struct.pack("i",0)
        return client.send(len1+len2+jsonstr);



def run():
    print "ngrokd-python v"+str(Ver)+"\r\n"
    ngrokdpy = NgrokdPython()
    ngrokdpy.main_thread()

run();