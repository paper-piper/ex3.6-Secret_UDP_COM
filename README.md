# Exercise 6.13 – Secret Communication Over Port Numbers

## 🕵️‍♂️ Mission Brief

Welcome, agent! Your mission, should you choose to accept it, involves top-secret communication. You will be assisting two covert operatives, Yoav and Maor, in their quest to pass clandestine messages across the digital divide, undetected by nefarious entities.

## 🎯 Purpose

Our operatives must transmit messages securely, without the risk of interception. Even if malicious actors were to sniff the network traffic, they'd be none the wiser. How, you ask? Through the cunning use of port numbers as a cipher!

## 🛠️ The Plan

The codebook for this operation is the ASCII table. Messages will be encoded one character at a time, using the ASCII value of each character as the port number for sending an empty UDP message. This method ensures that only someone with the key (i.e., this README) can decipher the message.

## 📜 Scripts to Use

- `py.client_message_secret`: This script, operated by the sender, prompts for a message and then transmits it covertly to the receiver. The server's IP is hardcoded for operational security.
- `py.server_message_secret`: This script, running on the receiver's machine, intercepts the incoming messages and deciphers them back into text.

## 🎁 Bonus Challenge

Given the unreliability of UDP (messages may arrive out of order or go missing), devise a method to ensure messages are received correctly and in the right sequence. Implement this enhanced protocol for an even more secure communication line.

## 📦 Requirements

- Python 3.x
- Scapy
- Two computers on the same network, designated as the client (sender) and server (receiver).

## 🔧 Setup

1. Ensure Python and Scapy are installed on both machines.
2. Deploy `py.client_message_secret` on the sender's machine.
3. Deploy `py.server_message_secret` on the receiver's machine.
4. Run the server script first to start listening.
5. Run the client script, enter your secret message, and watch the magic happen.

## 📖 Disclaimer

This project is for educational purposes only. Use these scripts responsibly and ethically.

Good luck, agents! Remember, in the world of covert communications, silence is golden, and port numbers are your best friend.
