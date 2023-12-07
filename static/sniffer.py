'''
from scapy.all import sniff

def packet_callback(packet):
    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        print(f"Capturado paquete IP - Origen: {ip_src}, Destino: {ip_dst}")

sniff(prn=packet_callback, store=0,)
'''

'''
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=sniffed_packet)

def sniffed_packet(packet):
    #if packet.haslayer(http.HTTPRequest):
        print(packet)

def main():
    sniff("Wi-Fi")

if __name__ == "__main__":
    main()
'''
'''
import scapy.all as scapy

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=sniffed_packet, filter="port 5000")

def sniffed_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"Capturado paquete IP - Origen: {ip_src}, Destino: {ip_dst}")

def main():
    sniff("")  # Reemplaza "Wi-Fi" con el nombre de la interfaz que deseas usar

if __name__ == "__main__":
    main()
'''

import socket
import os

# Crear un socket INET, STREAMing (raw)
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# Vincular el socket a una dirección y puerto
s.bind(('localhost', 5000))

# Recibir un paquete
while True:
    packet = s.recvfrom(65565)

    # El paquete es una tupla donde el primer elemento es la data
    packet = packet[0]

    # Convertir a string
    packet_str = str(packet)

    # Imprimir el paquete
    print(packet_str)

