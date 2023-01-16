from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp

frame = Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2='12:34:56:78:90:ab', addr3='12:34:56:78:90:ab')
frame /= Dot11Beacon(cap='ESS+privacy')
frame /= RadioTap()

# Add the SSID information element
ssid = input("SSID : ")
net_if = input("Network Interface : ")
frame /= Dot11Elt(ID='SSID',info=ssid)

while True:
	sendp(frame, iface=net_if, count=100, inter=.1)
