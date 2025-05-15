# GridAppSD Certificate Store

[![Python Tests](https://github.com/yourusername/gridappsd-certificate-store/actions/workflows/python-test.yml/badge.svg)](https://github.com/yourusername/gridappsd-certificate-store/actions/workflows/python-test.yml)
[![PyPI version](https://badge.fury.io/py/gridappsd-certificate-store.svg)](https://badge.fury.io/py/gridappsd-certificate-store)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A flexible and secure X.509 certificate generator for IEEE 2030.5 smart grid devices, IoT applications, and general TLS/HTTPS requirements.

## Features

- **Complete Certificate Generation**: Create CAs, device certificates, and self-signed certificates
- **IEEE 2030.5 Support**: Designed with IEEE 2030.5-2018 standard in mind for smart grid communications
- **Multiple Key Types**: Support for both RSA and Elliptic Curve cryptography
- **Flexible Subject Alternative Names**: Create certificates with URIs, DNS names, IP addresses, or email addresses
- **TLS 1.2+ Compliance**: Generate certificates that meet security requirements for modern TLS
- **Certificate Persistence**: Easily save and load certificates and private keys
- **Web Server Certificates**: Specialized method for generating HTTPS server certificates

## Installation

```bash
# Install from PyPI
pip install gridappsd-certificate-store

# Or with Poetry
poetry add gridappsd-certificate-store
```

## Quick Start

### Creating a CA Certificate

```python
from gridappsd_certs.generator import DeviceCertificateGenerator

# Initialize the generator
cert_gen = DeviceCertificateGenerator(key_type='rsa', key_size=2048)

# Create a CA certificate
ca_attrs = {
    'common_name': 'GridAppSD Root CA',
    'organization': 'GridAppSD',
    'country': 'US',
    'organizational_unit': 'Security'
}

ca_cert, ca_key = cert_gen.create_ca_certificate(ca_attrs, valid_days=3652)

# Save the certificate and key
cert_gen.save_certificate(ca_cert, 'ca_cert.pem')
cert_gen.save_private_key(ca_key, 'ca_key.pem', password='secure-password')
```

### Creating an IEEE 2030.5 Device Certificate

```python
# Create a device certificate for IEEE 2030.5
device_attrs = {
    'common_name': 'Smart Meter 101',
    'organization': 'GridAppSD',
    'country': 'US',
    'organizational_unit': 'Smart Meters',
    'serial_number': 'SM101-12345'
}

device_id = '44b0d6d5-aaaa-bbbb-cccc-4d3e17a3175b'
device_cert, device_key = cert_gen.create_device_certificate(
    device_attrs,
    ca_cert,
    ca_key,
    device_id=device_id,
    san_type='uri'  # Default for 2030.5 devices
)

# Save the device certificate and key
cert_gen.save_certificate(device_cert, 'device_cert.pem')
cert_gen.save_private_key(device_key, 'device_key.pem')
```

### Creating a Web Server Certificate

```python
# Create a certificate for a web server
web_attrs = {
    'common_name': 'gridappsd.example.org',
    'organization': 'GridAppSD',
    'country': 'US',
    'organizational_unit': 'Web Services'
}

domains = ['gridappsd.example.org', 'www.gridappsd.example.org']
web_cert, web_key = cert_gen.create_web_certificate(
    web_attrs,
    ca_cert,
    ca_key,
    domains=domains
)

# Save the web certificate and key
cert_gen.save_certificate(web_cert, 'web_cert.pem')
cert_gen.save_private_key(web_key, 'web_key.pem')
```

### Creating a Self-Signed Device Certificate

```python
# Create a self-signed certificate for an IoT device
iot_attrs = {
    'common_name': 'IoT Sensor 042',
    'organization': 'GridAppSD',
    'country': 'US'
}

from ipaddress import ip_address
iot_cert, iot_key = cert_gen.create_self_signed_device_cert(
    iot_attrs,
    san_type='ip',
    san_values=[ip_address('192.168.1.42')]
)

# Save the IoT device certificate and key
cert_gen.save_certificate(iot_cert, 'iot_cert.pem')
cert_gen.save_private_key(iot_key, 'iot_key.pem')
```

## Certificate Attributes

The following attributes can be included in certificate subject information:

| Dictionary Key | Description |
|----------------|-------------|
| `common_name` | The common name (CN) for the certificate |
| `country` | Two-letter country code (e.g., 'US') |
| `state` | State or province name |
| `locality` | City or locality name |
| `organization` | Organization name |
| `organizational_unit` | Department or unit within organization |
| `email` | Email address |
| `serial_number` | Serial number (useful for device identification) |

## Loading Existing Certificates

```python
# Load a certificate from a file
cert = cert_gen.load_certificate('device_cert.pem')

# Load a private key from a file (with or without password)
key = cert_gen.load_private_key('device_key.pem')
password_protected_key = cert_gen.load_private_key('ca_key.pem', password='secure-password')
```

## IEEE 2030.5 Specifics

The library is designed with IEEE 2030.5-2018 standard in mind, which requires:

- TLS 1.2 with AES-CCM mode of operation
- X.509 certificates for mutual authentication
- Device identification via UUID in Subject Alternative Name

When using this library for IEEE 2030.5 devices, ensure you use the `san_type='uri'` option with a proper UUID to meet the standard's requirements.

## Development

```bash
# Clone the repository
git clone https://github.com/yourusername/gridappsd-certificate-store.git
cd gridappsd-certificate-store

# Install dependencies with Poetry
poetry install

# Run tests
poetry run pytest

# Run tests with coverage
poetry run pytest --cov=gridappsd_certs
```

## License

BSD 3-Clause License

Copyright (c) 2023, GridAppSD Contributors
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.