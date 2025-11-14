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

```python
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

**Sample Input/Output:**
```
Enter the data bits: 1101011
Enter the generator polynomial: 1011
Encoded data (to be transmitted): 1101011110
Enter received data bits: 1101011110
✅ No error detected in received data.
```

---

### 🔹 Program 2: Hamming Code (Error Detection & Correction)

```python
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

**Sample Input/Output:**
```
Enter 4 data bits: 1011
Encoded 7-bit Hamming code: 0110011
Enter received 7-bit code: 0100011
❌ Error detected at position: 3
Corrected codeword: 0110011
Decoded data bits: 1011
```

---

## Experiment 2 - Remote Command Execution

### 🎯 Aim
To implement a remote command execution system using socket programming where a client can execute commands on a server machine.

---

### 🔹 Client Program

```python
import socket

s = socket.socket()
s.connect(("localhost", 4444))

while True:
    cmd = input("cmd> ")
    s.send(cmd.encode())
    if cmd == "quit":
        break
    print(s.recv(65535).decode(), end="")

s.close()
```

---

### 🔹 Server Program

```python
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
print("Running...")

while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn,), daemon=True).start()
```

**How to Run:**
1. Start server: `python server.py`
2. Start client: `python client.py`
3. Type commands in client terminal
4. Type `quit` to exit

---

## Experiment 4 - TCP and UDP Chat Applications

### 🎯 Aim
To implement chat applications using TCP (connection-oriented) and UDP (connectionless) protocols.

---

### 🔹 TCP Chat Server

```python
import socket
import threading


def handle_client(conn, addr):
    print(addr, "connected")
    while True:
        msg = conn.recv(1024).decode()
        if not msg or msg == "quit":
            break
        print(f"{addr}: {msg}")
        conn.send(f"Server: {msg}".encode())
    conn.close()


server = socket.socket()
server.bind(("localhost", 2345))
server.listen()
print("Server running...")

while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
```

---

### 🔹 TCP Chat Client

```python
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
print("Connected. Type 'quit' to exit.")

threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

while True:
    msg = input("You: ")
    client.send(msg.encode())
    if msg == "quit":
        break

client.close()
```

---

### 🔹 UDP Chat (Peer-to-Peer)

```python
import socket
import threading


def receive_messages(sock):
    while True:
        data, addr = sock.recvfrom(1024)
        print(f"\n{addr}: {data.decode()}")


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
my_port = int(input("Your port: "))
peer_port = int(input("Peer port: "))

sock.bind(("localhost", my_port))
threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()
print("Chat started! Type 'quit' to exit.")

while True:
    msg = input("You: ")
    sock.sendto(msg.encode(), ("localhost", peer_port))
    if msg == "quit":
        break

sock.close()
```

**How to Run UDP Chat:**
1. Open two terminals
2. Terminal 1: Enter port 5000, peer port 6000
3. Terminal 2: Enter port 6000, peer port 5000
4. Start chatting!

---

## Experiment 5 - Multi-threaded Socket Programming

### 🎯 Aim
To implement a multi-threaded server that handles multiple clients simultaneously and processes commands like ECHO, PING, and TALK.

---

### 🔹 Multi-threaded Server

```python
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
    print("Server started on localhost:12345")

    while True:
        client_socket, address = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, address))
        thread.start()


if __name__ == "__main__":
    start_server()
```

---

### 🔹 Client Program

```python
import socket


def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 12345))

    print("Connected to server!")
    print("Commands: ECHO <message>, PING, TALK <message>")
    print("Type 'quit' to exit.\n")

    while True:
        message = input("Enter command: ").strip()
        if message.lower() == "quit":
            break

        client.send(message.encode())
        response = client.recv(1024).decode()
        print(f"Server response: {response}")

    client.close()
    print("Disconnected from server")


if __name__ == "__main__":
    start_client()
```

**Commands:**
- `ECHO Hello` → Server replies: `Echo: Hello`
- `PING` → Server replies: `PONG`
- `TALK Hi` → Server replies: `Server says: Hi`

---

## Experiment 6 - File Transfer using TCP and UDP

### 🎯 Aim
To transfer files between client and server using both TCP (reliable) and UDP (fast) protocols.

---

### 🔹 TCP File Transfer - Server

```python
import socket

s = socket.socket()
s.bind(("localhost", 5000))
s.listen(1)
print("TCP Server waiting...")

c, a = s.accept()
filename = c.recv(1024).decode()

try:
    data = open(filename, "rb").read()
    c.send(data)
    print("File sent.")
except:
    c.send(b"ERROR: File not found")

c.close()
s.close()
```

---

### 🔹 TCP File Transfer - Client

```python
import socket

c = socket.socket()
c.connect(("localhost", 5000))

fname = input("Enter filename: ")
c.send(fname.encode())

data = c.recv(1000000)

if data.startswith(b"ERROR"):
    print("File not found")
else:
    open("received_" + fname, "wb").write(data)
    print("File saved.")

c.close()
```

---

### 🔹 UDP File Transfer - Server

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("localhost", 6000))
print("UDP Server waiting...")

fname, addr = s.recvfrom(1024)
fname = fname.decode()

try:
    data = open(fname, "rb").read()
    for i in range(0, len(data), 1024):
        s.sendto(data[i : i + 1024], addr)
    s.sendto(b"END", addr)
    print("File sent.")
except:
    s.sendto(b"ERROR: File not found", addr)

s.close()
```

---

### 🔹 UDP File Transfer - Client

```python
import socket

c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

fname = input("Enter filename: ")
c.sendto(fname.encode(), ("localhost", 6000))

data = b""
while True:
    chunk, a = c.recvfrom(1024)
    if chunk == b"END":
        break
    if chunk.startswith(b"ERROR"):
        print("File not found")
        exit()
    data += chunk

open("received_" + fname, "wb").write(data)
print("File saved.")
c.close()
```

**How to Run:**
1. Place a test file (e.g., `test.txt`) in server folder
2. Run server: `python tcp_server.py` or `python udp_server.py`
3. Run client: `python tcp_client.py` or `python udp_client.py`
4. Enter filename when prompted
5. File will be saved as `received_<filename>`

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
