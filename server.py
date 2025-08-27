#!/usr/bin/env python3
import sys
import threading
from pathlib import Path
import paho.mqtt.client as mqtt

BASE_DIR = Path(__file__).resolve().parent          # .../privacy_protocol
PROTO_DIR = BASE_DIR / "protocol"
for p in (BASE_DIR, PROTO_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from protocol.secure_channel import SecureChannel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

SERVER_PRIV_PEM = BASE_DIR / "server_priv.pem"
SERVER_PUB_PEM  = BASE_DIR / "server_pub.pem"
DEVICE_PUB_PEM  = BASE_DIR / "device_pub.pem"

BROKER_IP   = "0.0.0.0"          # Mosquitto on this Kali box
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
server_priv = load_or_create_private_key(SERVER_PRIV_PEM)
sc.ecdh.private_key = server_priv
sc.ecdh.public_key  = server_priv.public_key()

write_public_key(SERVER_PUB_PEM, sc.ecdh.public_key)
print("[Kali] Wrote server_pub.pem")


if not DEVICE_PUB_PEM.exists():
    raise FileNotFoundError("[Kali] device_pub.pem not found. Copy it from the Pi before running.")
sc.set_peer_public_key_pem(DEVICE_PUB_PEM.read_bytes())
print("[Kali] Shared secret derived—ready.")

def on_connect(client, userdata, flags, rc):
    print(f"[Kali] MQTT connected rc={rc}")
    client.subscribe(TOPIC_DATA)

def on_message(client, userdata, msg):
    pt = sc.decrypt_and_verify(msg.payload
    if pt is None:
        print("[Kali] HMAC verification FAILED or payload malformed.")
        return
    try:
        print(f"[Kali] Decrypted from device: {pt.decode('utf-8')}")
    except Exception:
        print(f"[Kali] Decrypted (bytes): {pt!r}")

def input_loop():
    while True:
        try:
            text = input()
        except EOFError:
            break
        if not text.strip():
            continue
        payload = sc.encrypt_and_authenticate(text.encode("utf-8"))
        client.publish(TOPIC_CMD, payload, qos=0, retain=False)

client = mqtt.Client(protocol=mqtt.MQTTv311)
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER_IP, 1883, 60)
#client = mqtt.Client(protocol=mqtt.MQTTv311)
#client.username_pw_set("iotuser", "tj@001")

# Start stdin->device command loop in a background thread
threading.Thread(target=input_loop, daemon=True).start()

print("[Kali] Type a command and press Enter to send to device.")
client.loop_forever()
