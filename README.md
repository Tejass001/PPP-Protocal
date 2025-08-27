# Privacy Preserving Communication Protocol
This thesis presents the design and implementation of a privacy-preserving communication protocol for secure data transmission in resource-constrained environments, specifically in IoT networks. The system utilizes advanced cryptographic techniques, including
ChaCha20 encryption, Elliptic Curve Diffie-Hellman (ECDH) key exchange, and HMAC
authentication to ensure data confidentiality, integrity, and authentication. The protocol is designed to address the challenges of securing communication between devices in
IoT networks, where low-power, low-latency, and efficient encryption are crucial.
The MQTT protocol is employed for real-time message exchange, enabling efficient
publish-subscribe communication between the IoT devices and the server. The system
demonstrates end-to-end encryption, ensuring that data remains secure from interception and tampering during transmission. The key exchange mechanism based on ECDH
enables the secure derivation of shared secrets, and the HMAC algorithm is used to
authenticate the messages, preventing unauthorized access or modifications.
The protocol is tested, where encrypted messages are successfully transmitted between
the IoT device and the server. The system’s performance, security, and scalability
are evaluated under different network conditions, demonstrating its suitability for realworld applications in secure messaging and IoT communications

#Key Features

ChaCha20 Encryption: A lightweight, high-performance encryption algorithm that is well-suited for resource-constrained IoT devices. It encrypts data in transit, ensuring confidentiality while maintaining low power consumption.

Elliptic Curve Diffie-Hellman (ECDH): A key exchange protocol that facilitates secure generation of shared keys between devices and the server, enabling symmetric encryption for data confidentiality.

HMAC for Integrity: A Hash-Based Message Authentication Code (HMAC) ensures that the data received has not been tampered with during transmission.

MQTT Protocol: A lightweight messaging protocol used for secure communication between IoT devices and the server. MQTT ensures efficient data transmission with minimal overhead.

##Architecture

The architecture consists of a Raspberry Pi-based IoT device, which communicates with a server using MQTT. The IoT device generates sensor data, encrypts it using ChaCha20, performs key exchange with the server using ECDH, and transmits the encrypted data over MQTT. The server then decrypts the data, verifies its integrity using HMAC, and processes it for further action.

##Technologies Used

Programming Languages: Python 3.xChallenges Faced

Efficient encryption and decryption on resource-constrained devices.

Secure and lightweight key exchange for maintaining session integrity without compromising performance.

Ensuring MQTT broker configuration for secure communication.

##Future Work

Extend the protocol to handle more complex IoT systems with a larger number of devices.

Investigate post-quantum cryptographic solutions for future-proofing against quantum computing threats.

##Contact Information

For more details or questions, feel free to contact the project maintainer at: Tejass001@github.com

