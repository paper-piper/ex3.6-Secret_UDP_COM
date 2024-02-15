"""
Author: Yoni Reichert
Program name: ex3.6-Secret-UDP-COM
Description: sends secret messages through the usage of sending empty message to different ports
Date: 03-02-2023
"""

from scapy.all import *
from scapy.layers.inet import *
import logging

logging.basicConfig(
    filename='Sender.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(lineno)d - %(levelname)s - %(message)s',
    datefmt='%m-%d %H:%M:%S'
)
logger = logging.getLogger('Sender.log')

dIP = "192.168.1.106"
COM_END = chr(3)


def send_message(message):
    """
    Send a string ascii message according to the secret ports protocol
    :param message: the message that is ment to be sent
    :return bool: an indicator for the function's success
    """
    if not validate_message(message):
        return False
    for char in message:
        try:
            send_packet(char)
        except Scapy_Exception as s:
            logger.exception(f"Received scapy exception while sending char {char}: {s}")
            return False
    send_packet(COM_END)
    return True


def send_packet(char):
    """
    send a single packet with no content to a port according to the ascii value of the char
    :param char: the port indicator
    :return: nothing
    """
    char_packet = create_packet(char)
    send(char_packet, verbose=0)


def create_packet(char):
    """
    create an empty packet with dport set to the char ascii value
    :param char: the port indicator
    :return: the created packet
    """
    ascii_value = ord(char)
    char_packet = IP(dst=dIP) / UDP(dport=ascii_value) / b""  # empty payload
    return char_packet


def validate_message(message):
    try:
        for char in message:
            char_value = ord(char)
            if not 0 <= char_value <= 127:
                return False
    except IndexError as i:
        logger.error(f"received index error {i}")
    return True


def main():
    message = input("Enter message: ")
    if send_message(message):
        logger.info(f"Send message '{message}' to IP '{dIP}'")
        print(f"Sent message '{message}' successfully!")


if __name__ == '__main__':
    assert validate_message("Valid")
    assert not validate_message(f"Invalid {chr(128)}")
    main()
