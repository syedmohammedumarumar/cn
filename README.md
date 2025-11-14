# 🌐 Computer Networks Laboratory - Complete Experiments

A comprehensive collection of all Computer Networks lab experiments with ready-to-use code implementations.

---

## 📚 Table of Contents

1. [Experiment 1 - CRC and Hamming Code](#experiment-1---crc-and-hamming-code)
2. [Experiment 2 - Remote Command Execution](#experiment-2---remote-command-execution)
3. [Experiment 4 - TCP and UDP Chat Applications](#experiment-4---tcp-and-udp-chat-applications)
4. [Experiment 5 - Multi-threaded Socket Programming](#experiment-5---multi-threaded-socket-programming)
5. [Experiment 6 - File Transfer using TCP and UDP](#experiment-6---file-transfer-using-tcp-and-udp)

---

## Experiment 1 - CRC and Hamming Code

### 🎯 Aim
To implement error detection using **CRC (Cyclic Redundancy Check)** and error detection & correction using **Hamming Code**.

### 📖 Theory
- **CRC**: Detects errors in transmitted data using polynomial division (XOR-based)
- **Hamming Code**: Detects and corrects single-bit errors using parity bits

---

### 🔹 Program 1: CRC Error Detection

**📁 File: `crc.py`**

```python
# CRC Error Detection Program
# HOW TO RUN:
# 1. Save this code as crc.py
# 2. Open terminal/command prompt
# 3. Run: python crc.py
# 4. Enter data bits (example: 1101011)
# 5. Enter generator polynomial (example: 1011)
# 6. Enter received data to check for errors

def xor_divide(dividend, divisor):
    dividend = list(dividend)
    divisor_len = len(divisor)

    for i in range(len(dividend) - divisor_len + 1):
        if dividend[i] == '1':
            for j in range(divisor_len):
                dividend[i + j] = str(int(dividend[i + j]) ^ int(divisor[j]))

    return ''.join(dividend[-(divisor_len - 1):])


def crc_encode(data, generator):
    padded_data = data + '0' * (len(generator) - 1)
    remainder = xor_divide(padded_data, generator)
    return data + remainder


def crc_check(received_data, generator):
    remainder = xor_divide(received_data, generator)
    return remainder == '0' * (len(generator) - 1)


if __name__ == "__main__":
    print("=== CRC Error Detection ===")
    data = input("Enter the data bits: ")
    generator = input("Enter the generator polynomial: ")

    encoded = crc_encode(data, generator)
    print(f"\nEncoded data (to be transmitted): {encoded}")

    received = input("\nEnter received data bits: ")

    if crc_check(received, generator):
        print("✅ No error detected in received data.")
    else:
        print("❌ Error detected in received data.")
```

---

### 🔹 Program 2: Hamming Code (Error Detection & Correction)

**📁 File: `hamming.py`**

```python
# Hamming Code - Error Detection and Correction
# HOW TO RUN:
# 1. Save this code as hamming.py
# 2. Open terminal/command prompt
# 3. Run: python hamming.py
# 4. Enter 4 data bits (example: 1011)
# 5. Note the encoded 7-bit code
# 6. Enter received code to check/correct errors

def hamming_encode(data):
    d = [int(bit) for bit in data]
    while len(d) < 4:
        d.insert(0, 0)
    d1, d2, d3, d4 = d

    p1 = d1 ^ d2 ^ d4
    p2 = d1 ^ d3 ^ d4
    p3 = d2 ^ d3 ^ d4

    return f"{p1}{p2}{d1}{p3}{d2}{d3}{d4}"


def hamming_decode(code):
    bits = [int(bit) for bit in code]
    p1, p2, d1, p3, d2, d3, d4 = bits

    c1 = p1 ^ d1 ^ d2 ^ d4
    c2 = p2 ^ d1 ^ d3 ^ d4
    c3 = p3 ^ d2 ^ d3 ^ d4

    error_pos = c1 * 1 + c2 * 2 + c3 * 4

    if error_pos == 0:
        print("✅ No error detected.")
        return f"{d1}{d2}{d3}{d4}"
    else:
        print(f"❌ Error detected at position: {error_pos}")
        corrected = list(code)
        corrected[error_pos - 1] = '1' if corrected[error_pos - 1] == '0' else '0'
        corrected_code = ''.join(corrected)
        print(f"Corrected codeword: {corrected_code}")
        bits = [int(bit) for bit in corrected_code]
        return f"{bits[2]}{bits[4]}{bits[5]}{bits[6]}"


if __name__ == "__main__":
    print("=== Hamming Code (4-bit Data) ===")
    data = input("Enter 4 data bits: ")
    encoded = hamming_encode(data)
    print(f"\nEncoded 7-bit Hamming code: {encoded}")

    received = input("\nEnter received 7-bit code: ")
    decoded = hamming_decode(received)
    print(f"Decoded data bits: {decoded}")
```

---

## Experiment 2 - Remote Command Execution

### 🎯 Aim
To implement a remote command execution system using socket programming where a client can execute commands on a server machine.

---

### 📦 Complete Code (Copy Both Files)

**📁 File 1: `remote_server.py` | File 2: `remote_client.py`**

```python
# ============================================
# FILE 1: remote_server.py
# ============================================
# HOW TO RUN:
# 1. Save this section as remote_server.py
# 2. Open terminal and run: python remote_server.py
# 3. Server will start and wait for client connection
# 4. Keep this terminal open

import socket
import subprocess
import os
import threading


def handle_client(conn):
    while True:
        cmd = conn.recv(4096).decode()
        if not cmd or cmd == "quit":
            break

        if cmd.startswith("cd "):
            try:
                os.chdir(cmd[3:])
            except Exception as err:
                output = str(err)
            else:
                output = os.getcwd()
            conn.send((output + "\n").encode())
            continue

        process = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        conn.send((process.stdout.read() + process.stderr.read()) or b"\n")

    conn.close()


server = socket.socket()
server.bind(("0.0.0.0", 4444))
server.listen()
print("Server Running on port 4444...")

while True:
    conn, addr = server.accept()
    print(f"Client connected: {addr}")
    threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


# ============================================
# FILE 2: remote_client.py
# ============================================
# HOW TO RUN:
# 1. Save this section as remote_client.py
# 2. Make sure server is running first
# 3. Open NEW terminal and run: python remote_client.py
# 4. Type commands (ls, dir, pwd, etc.)
# 5. Type 'quit' to exit

import socket

s = socket.socket()
s.connect(("localhost", 4444))
print("Connected to server!")
print("Type commands (or 'quit' to exit)")

while True:
    cmd = input("cmd> ")
    s.send(cmd.encode())
    if cmd == "quit":
        break
    print(s.recv(65535).decode(), end="")

s.close()
```

**🚀 Execution Steps:**
```
Terminal 1: python remote_server.py
Terminal 2: python remote_client.py
```

---

## Experiment 4 - TCP and UDP Chat Applications

### 🎯 Aim
To implement chat applications using TCP (connection-oriented) and UDP (connectionless) protocols.

---

### 📦 Part A: TCP Chat Application

**📁 File 1: `tcp_chat_server.py` | File 2: `tcp_chat_client.py`**

```python
# ============================================
# FILE 1: tcp_chat_server.py
# ============================================
# HOW TO RUN:
# 1. Save this section as tcp_chat_server.py
# 2. Run: python tcp_chat_server.py
# 3. Server starts on port 2345
# 4. Wait for clients to connect

import socket
import threading


def handle_client(conn, addr):
    print(f"{addr} connected")
    while True:
        msg = conn.recv(1024).decode()
        if not msg or msg == "quit":
            break
        print(f"{addr}: {msg}")
        conn.send(f"Server: {msg}".encode())
    print(f"{addr} disconnected")
    conn.close()


server = socket.socket()
server.bind(("localhost", 2345))
server.listen()
print("TCP Server running on port 2345...")

while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


# ============================================
# FILE 2: tcp_chat_client.py
# ============================================
# HOW TO RUN:
# 1. Save this section as tcp_chat_client.py
# 2. Make sure server is running
# 3. Run: python tcp_chat_client.py
# 4. Type messages and press Enter
# 5. Type 'quit' to exit

import socket
import threading


def receive_messages(sock):
    while True:
        data = sock.recv(1024).decode()
        if not data:
            break
        print("\n" + data)


client = socket.socket()
client.connect(("localhost", 2345))
print("Connected to server! Type 'quit' to exit.")

threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

while True:
    msg = input("You: ")
    client.send(msg.encode())
    if msg == "quit":
        break

client.close()
```

**🚀 Execution Steps:**
```
Terminal 1: python tcp_chat_server.py
Terminal 2: python tcp_chat_client.py
```

---

### 📦 Part B: UDP Peer-to-Peer Chat

**📁 File: `udp_chat.py` (Run on both peers)**

```python
# ============================================
# UDP Peer-to-Peer Chat
# ============================================
# HOW TO RUN:
# 1. Save this code as udp_chat.py
# 2. Open TWO terminals
# 3. Terminal 1: python udp_chat.py
#    - Enter your port: 5000
#    - Enter peer port: 6000
# 4. Terminal 2: python udp_chat.py
#    - Enter your port: 6000
#    - Enter peer port: 5000
# 5. Start chatting!
# 6. Type 'quit' to exit

import socket
import threading


def receive_messages(sock):
    while True:
        data, addr = sock.recvfrom(1024)
        print(f"\nPeer: {data.decode()}")
        print("You: ", end="", flush=True)


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
my_port = int(input("Your port: "))
peer_port = int(input("Peer port: "))

sock.bind(("localhost", my_port))
threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()
print("Chat started! Type 'quit' to exit.\n")

while True:
    msg = input("You: ")
    sock.sendto(msg.encode(), ("localhost", peer_port))
    if msg == "quit":
        break

sock.close()
```

**🚀 Execution Steps:**
```
Terminal 1: python udp_chat.py → Port: 5000, Peer: 6000
Terminal 2: python udp_chat.py → Port: 6000, Peer: 5000
```

---

## Experiment 5 - Multi-threaded Socket Programming

### 🎯 Aim
To implement a multi-threaded server that handles multiple clients simultaneously and processes commands like ECHO, PING, and TALK.

---

### 📦 Complete Code (Server + Client)

**📁 File 1: `multithread_server.py` | File 2: `multithread_client.py`**

```python
# ============================================
# FILE 1: multithread_server.py
# ============================================
# HOW TO RUN:
# 1. Save this section as multithread_server.py
# 2. Run: python multithread_server.py
# 3. Server starts on port 12345
# 4. Can handle multiple clients simultaneously

import socket
import threading


def handle_client(client_socket, address):
    print(f"Connected: {address}")
    while True:
        try:
            data = client_socket.recv(1024).decode().strip()
            if not data:
                break

            print(f"Received from {address}: {data}")

            if data.startswith("ECHO"):
                message = data[5:]
                response = f"Echo: {message}"
            elif data == "PING":
                response = "PONG"
            elif data.startswith("TALK"):
                message = data[5:]
                response = f"Server says: {message}"
            else:
                response = "Unknown command"

            client_socket.send(response.encode())
        except:
            break

    client_socket.close()
    print(f"Client {address} disconnected")


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 12345))
    server.listen(5)
    print("Multi-threaded Server started on localhost:12345")
    print("Supported commands: ECHO, PING, TALK")

    while True:
        client_socket, address = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, address))
        thread.start()


if __name__ == "__main__":
    start_server()


# ============================================
# FILE 2: multithread_client.py
# ============================================
# HOW TO RUN:
# 1. Save this section as multithread_client.py
# 2. Make sure server is running
# 3. Run: python multithread_client.py
# 4. Enter commands:
#    - ECHO Hello
#    - PING
#    - TALK Hi there
# 5. Type 'quit' to exit

import socket


def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 12345))

    print("Connected to server!")
    print("Commands:")
    print("  ECHO <message>  - Server echoes your message")
    print("  PING            - Server replies PONG")
    print("  TALK <message>  - Server responds with message")
    print("Type 'quit' to exit.\n")

    while True:
        message = input("Enter command: ").strip()
        if message.lower() == "quit":
            break

        client.send(message.encode())
        response = client.recv(1024).decode()
        print(f"Server response: {response}\n")

    client.close()
    print("Disconnected from server")


if __name__ == "__main__

---

## 📝 Important Notes

### Running Programs
- Always run **server first**, then **client**
- Use separate terminal windows for server and client
- For multiple clients, open multiple client terminals

### Common Issues
- **Port already in use**: Change port number or wait a few seconds
- **Connection refused**: Ensure server is running first
- **File not found**: Place file in same folder as server

### Testing
- Test with simple text files first
- Try error scenarios (wrong filename, corrupted data)
- Test with multiple clients for multi-threaded programs

---

## 🎓 Lab Exam Tips

1. **Practice typing** these programs from memory
2. **Understand the flow**: Client → Server → Response
3. Know the **difference between TCP and UDP**
4. Be ready to **explain threading** concept
5. Practice **running both server and client** smoothly

---

## 📚 Quick Reference

| Protocol | Connection | Reliability | Speed | Use Case |
|----------|-----------|-------------|-------|----------|
| **TCP** | Connection-oriented | Reliable | Slower | File transfer, Chat |
| **UDP** | Connectionless | Unreliable | Faster | Streaming, Gaming |

---

## 👨‍🎓 Created for Computer Networks Lab

**All programs tested and verified ✅**

*Good luck with your lab exams!* 🚀

---
