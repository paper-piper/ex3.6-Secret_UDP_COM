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

SENDER_MESSAGE = ""


def filter_packet(char_packet):
    """
    Filter packets to only include UDP with dport in ASCII range and empty payload
    :param char_packet: the packet to be checked
    :return bool: True if packet matches criteria, False otherwise
    """
    is_udp = UDP in char_packet
    if is_udp and char_packet[UDP].dport <= 127:
        payload = char_packet[UDP].payload
        if isinstance(payload, Padding) and payload.load == b'\x00' * len(payload.load):
            return True
    return False


def process_packet(char_packet):
    """
    Process a packet to extract the character from the dport and log it
    :param char_packet: the packet to be processed
    :return: None
    """
    global SENDER_MESSAGE
    try:
        char_value = char_packet[UDP].dport
        if char_value == 3:
            logger.info(f"Reached the end of a message: {SENDER_MESSAGE}")
            print(f"Received Message! \r\n {SENDER_MESSAGE}")
            SENDER_MESSAGE = ""
        else:
            char = chr(char_value)
            logger.info(f"Received character: {char}")
            SENDER_MESSAGE += char
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
