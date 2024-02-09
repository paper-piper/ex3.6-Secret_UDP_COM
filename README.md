# Exercise 6.13 – Secret Communication Over Port Numbers

## 🕵️‍♂️ Mission Accomplished
Agents, congratulations on completing your mission! With your expertise, Yoav and Maor have successfully established a system for passing secret messages across the network, invisible to any prying eyes.

## 🎯 Objective Achieved
Our operatives have transcended traditional communication methods to transmit messages securely. By ingeniously employing port numbers as a cipher, they've ensured complete invisibility from network surveillance.

## 🛠️ Strategy Deployed
Leveraging the ASCII table as their codebook, our team encoded messages character by character. Each character's ASCII value determined the port number for sending an empty UDP message—a technique that guaranteed the message's secrecy.

## 📜 Scripts Developed
- `client_message_secret.py`: Operated by the sender, this script prompts for a message and then transmits it covertly.
- `server_message_secret.py`: Situated on the receiver's end, this script captures and deciphers the incoming messages.

## 📦 Project Setup
- **Requirements**: Python 3.x, Scapy, and two computers on the same network.
- **Execution**:
  1. Install Python and Scapy on both machines.
  2. Deploy `client_message_secret.py` on the sender's machine.
  3. Deploy `server_message_secret.py` on the receiver's machine.
  4. Run the server script to start listening.
  5. Execute the client script, enter the secret message, and observe the operation.

## 📖 Disclaimer
This project, designed strictly for educational purposes, demonstrates responsible and ethical use of scripting for secure communication.

**Agents, your silent work has spoken volumes. In the realm of covert operations, you've proven that with the right knowledge, port numbers can indeed be powerful allies.**
