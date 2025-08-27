#!/usr/bin/env python3
import sys, json, threading
from pathlib import Path
import paho.mqtt.client as mqtt

BASE_DIR = Path(__file__).resolve().parent
PROTO_DIR = BASE_DIR / "protocol"
for p in (BASE_DIR, PROTO_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


from protocol.secure_channel import SecureChannel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

DEVICE_PRIV_PEM = BASE_DIR / "device_priv.pem"
DEVICE_PUB_PEM  = BASE_DIR / "device_pub.pem"
SERVER_PUB_PEM  = BASE_DIR / "server_pub.pem"

BROKER_IP   = "192.168.1.33"     # Kali IP (bridged)
TOPIC_DATA  = "iot/device/data"  # device -> server
TOPIC_CMD   = "iot/device/cmd"   # server -> device

def load_or_create_private_key(priv_path: Path):
    if priv_path.exists():
        return serialization.load_pem_private_key(
            priv_path.read_bytes(), password=None, backend=default_backend()
        )
    key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    priv_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return key

def write_public_key(pub_path: Path, public_key):
    pub_path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

sc = SecureChannel()
device_priv = load_or_create_private_key(DEVICE_PRIV_PEM)
sc.ecdh.private_key = device_priv
sc.ecdh.public_key  = device_priv.public_key()


write_public_key(DEVICE_PUB_PEM, sc.ecdh.public_key)
print("[Pi] Wrote device_pub.pem")

if not SERVER_PUB_PEM.exists():
    raise FileNotFoundError("[Pi] server_pub.pem not found. Copy it from Kali before running.")
sc.set_peer_public_key_pem(SERVER_PUB_PEM.read_bytes())
print("[Pi] Shared secret derived—ready.")


def on_connect(client, userdata, flags, rc):
    print(f"[Pi] MQTT connected rc={rc}")
    client.subscribe(TOPIC_CMD)

    reading = {"temperature": 24.9, "humidity": 58}
    payload = sc.encrypt_and_authenticate(json.dumps(reading).encode("utf-8"))
    client.publish(TOPIC_DATA, payload, qos=0, retain=False)
    print("[Pi] Sent initial encrypted reading.")

def on_message(client, userdata, msg):
    # Server -> Device messages (live commands)
    pt = sc.decrypt_and_verify(msg.payload)
    if pt is None:
        print("[Pi] HMAC verification FAILED or payload malformed.")
        return
    try:
        print(f"[Pi] Decrypted command from server: {pt.decode('utf-8')}")
    except Exception:
        print(f"[Pi] Decrypted (bytes): {pt!r}")


def input_loop():
    # Read lines from keyboard and send to server (encrypted)
    while True:
        try:
            text = input()
        except EOFError:
            break
        if not text.strip():
            continue
        payload = sc.encrypt_and_authenticate(text.encode("utf-8"))
        client.publish(TOPIC_DATA, payload, qos=0, retain=False)


client = mqtt.Client(protocol=mqtt.MQTTv311)
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER_IP, 1883, 60)
#client = mqtt.Client(protocol=mqtt.MQTTv311)
#client.username_pw_set("iotuser", "tj@001")

# Start stdin->server loop in background
threading.Thread(target=input_loop, daemon=True).start()

print("[Pi] Type a message and press Enter to send to server.")
client.loop_forever()



