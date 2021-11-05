#!/usr/bin/python3
# -*- coding: utf-8 -*-
import ssl
import socket
import sys
import re
import sys
import subprocess
from datetime import datetime as dt

URL = 'ddnsclient.onamae.com'
PORT = 65010

USERID = 00000000            # お名前.comのID
PASSWD = "XXXXXXXXX"         # お名前.comのパスワード
HOSTNAME = ""                # サブドメイン
DOMNAME = "xxxxxx.com"       # ドメイン名

def sendMsg(conn, msg):
    print(msg)
    msg_bytes = msg.encode()
    conn.sendall(msg_bytes)

def changeRecord(IPADDRESS):
    context = ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.verify_mode = ssl.CERT_NONE
    context.check_hostname = False
    conn = context.wrap_socket(socket.socket(socket.AF_INET),
            server_hostname=URL)
    conn.connect((URL, PORT))
    ret = conn.recv(1024)
    print(ret)

    sendMsg(conn,"LOGIN\n")
    sendMsg(conn,"USERID:" + str(USERID) + "\n")
    sendMsg(conn,"PASSWORD:" + PASSWD + "\n")
    sendMsg(conn,".\n")
    print(conn.recv(1024))
    sendMsg(conn,"MODIP\n")
    sendMsg(conn,"HOSTNAME:" + HOSTNAME + "\n") 
    sendMsg(conn,"DOMNAME:" + DOMNAME + "\n")
    sendMsg(conn,"IPV4:" + IPADDRESS + "\n")
    sendMsg(conn,".\n")
    print(conn.recv(1024))
    sendMsg(conn,"LOGOUT\n")
    sendMsg(conn,".\n")
    print(conn.recv(1024))

if __name__ == "__main__":
    try:
        ip = subprocess.Popen("curl globalip.me", stdout=subprocess.PIPE,shell=True).stdout.readlines()[0].decode()
    except:
        print("error occured!")
        sys.exit()

    lastip = open("lastip.txt","r", encoding="utf-8").read()
    if(lastip == ""):
        lastip = ip
    with open("lastip.txt","w") as f:
        f.write(str(ip))

    if ip != lastip and re.match(r'^[\d\.]+$',ip):
        print("IP address is change!")
        changeRecord(ip)