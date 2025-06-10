import socket

target_ip = "127.0.0.1"
target_port = 80  

payload = "admin password attempt"

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, target_port))
    s.send(payload.encode())
    s.close()
    print("Intrusion payload sent.")
except Exception as e:
    print(f"Error sending packet: {e}")
