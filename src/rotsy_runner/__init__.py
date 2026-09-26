"""rotsy-runner — the execution side of Rotsy.

A runner executes static container-image scans (Trivy, Grype) for a Rotsy
server and talks to nothing else: it receives its scanner binaries and
vulnerability databases from that server, reads images through that server's
job-scoped registry proxy, and reports results back to it. It needs no
Internet access and holds no registry or notification credentials.
"""

__version__ = "1.0.0"

#: The runner agent protocol version this build speaks (see docs/PROTOCOL.md).
PROTOCOL_VERSION = 1
