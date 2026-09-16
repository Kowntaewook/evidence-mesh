# Offline TLS fixture credentials

`tls-v04-certificate.pem` and `tls-v04-public-test-key.pem` are public, disposable
test credentials generated for EvidenceMesh's inert SSL MemoryBIO fixture.
They are not production credentials and provide no trust or authentication.

`tests/test_network_v04.py` creates a real TLS 1.2 handshake, HTTP request and
response entirely in memory. It writes a PCAPNG and session key log into the
test's temporary directory. No socket, remote endpoint or live capture is used.

The actual TShark test verifies metadata-only results without the key log, and
HTTP body recovery with the explicitly supplied key log. It also checks that
the original key log is unchanged. OpenSSL is only needed to regenerate the
checked-in test certificate, not to run the test or the application.
