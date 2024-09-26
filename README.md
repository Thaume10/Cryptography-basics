This project showcases secure communication using a custom SSL/TLS protocol to protect interactions between clients and the server. Public-key certificates are used for identity verification, and RSA encryption ensures message security.

Key Components:

  SecureServer:
    Manages SSL/TLS connections with clients.
    Verifies client certificates and handles encrypted messages.
    Maintains client lists and manages secure groups for message encryption.
    
  SecureClient:
    Encrypts messages with the server's public key and handles communication securely.
    Manages RSA key pairs and X.509 certificates for secure messaging.

Cryptographic Utilities (UtilsCrypto):
  Provides methods for encryption, decryption, signature creation, and verification.
  Key pair and self-signed certificate generation.

Features:
  SSL/TLS for secure communication.
  Public-key encryption (RSA) with X.509 certificates.
  Client and server authentication.
  Secure message exchange with digital signatures.

Future Improvements:
  Implement certificate authority (CA) for robust certificate management.
  Add forward secrecy for enhanced security in sessions.
  Extend functionality for secure file transfers or email communication.
