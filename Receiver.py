from scapy.all import *
from scapy.layers.inet import *

import logging

# Setup logging
logging.basicConfig(
    filename='Receiver.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(lineno)d - %(levelname)s - %(message)s',
    datefmt='%m-%d %H:%M:%S'
)
logger = logging.getLogger('Receiver.log')


def filter_packet(packet):
    """
    Filter packets to only include UDP with dport in ASCII range and empty payload
    :param packet: the packet to be checked
    :return bool: True if packet matches criteria, False otherwise
    """
    return UDP in packet and packet[UDP].dport <= 127 and (not packet[UDP].payload or len(packet[UDP].payload) == 0)


def process_packet(packet):
    """
    Process a packet to extract the character from the dport and log it
    :param packet: the packet to be processed
    :return: None
    """
    try:
        char = chr(packet[UDP].dport)
        logger.info(f"Received character: {char}")
        print(f"Received: {char}")
    except ValueError as e:
        logger.exception(f"Error processing packet: {e}")


def sniff_packets():
    """
    Sniff for UDP packets with dport in the ASCII range and empty payload, and process them
    :return: None
    """
    sniff(lfilter=filter_packet, prn=process_packet, store=0)


def main():
    logger.info("Starting receiver to listen for secret messages.")
    print("Listening for secret messages...")
    sniff_packets()


if __name__ == '__main__':
    main()
