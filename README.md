## A lightweight and fast ECDSA implementation

### Overview

This is a Ruby implementation of the Elliptic Curve Digital Signature Algorithm. It works by wrapping the built-in openSSl Ruby module.

### Installation

To install StarkBank`s ECDSA-Ruby, run:

```sh
gem install starkbank-ecdsa
```

### Speed

We ran a test on Ruby 2.6.3 on a MAC Pro i5 2019. The library ran 100 times and showed the average times displayed bellow:

| Library            | sign          | verify  |
| ------------------ |:-------------:| -------:|
| starkbank-ecdsa    |     0.5ms     | 0.4ms  |


### Compatibility

ECDSA-Ruby uses the built-in openSSL Ruby library, which has to be [linked against the system open SSL during Ruby build to work](https://docs.ruby-lang.org/en/2.3.0/OpenSSL.html), if your ruby version is 2.3 or lower. It should work right out of the box on 2.4+, though.


### Sample Code

How to sign a json message for [Stark Bank]:

```ruby
require 'starkbank-ecdsa'
require "json"

# Generate privateKey from PEM string
privateKey = EllipticCurve::PrivateKey.fromPem("-----BEGIN EC PARAMETERS-----\nBgUrgQQACg==\n-----END EC PARAMETERS-----\n-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIODvZuS34wFbt0X53+P5EnSj6tMjfVK01dD1dgDH02RzoAcGBSuBBAAK\noUQDQgAE/nvHu/SQQaos9TUljQsUuKI15Zr5SabPrbwtbfT/408rkVVzq8vAisbB\nRmpeRREXj5aog/Mq8RrdYy75W9q/Ig==\n-----END EC PRIVATE KEY-----\n")

# Create message from json
message = {
    "transfers": [
        {
            "amount": 100000000,
            "taxId": "594.739.480-42",
            "name": "Daenerys Targaryen Stormborn",
            "bankCode": "341",
            "branchCode": "2201",
            "accountNumber": "76543-8",
            "tags": ["daenerys", "targaryen", "transfer-1-external-id"]
        }
    ]
}.to_json

signature = EllipticCurve::Ecdsa.sign(message, privateKey)

# Generate Signature in base64. This result can be sent to Stark Bank in header as Digital-Signature parameter
puts signature.toBase64()

# To double check if message matches the signature
publicKey = privateKey.publicKey()

puts EllipticCurve::Ecdsa.verify(message, signature, publicKey)
```

Simple use:

```ruby
require 'starkbank-ecdsa'

# Generate new Keys
privateKey = EllipticCurve::PrivateKey.new()
publicKey = privateKey.publicKey()

message = "My test message"

# Generate Signature
signature = EllipticCurve::Ecdsa.sign(message, privateKey)

# Verify if signature is valid
puts EllipticCurve::Ecdsa.verify(message, signature, publicKey)
```

### OpenSSL

This library is compatible with OpenSSL, so you can use it to generate keys:

```
openssl ecparam -name secp256k1 -genkey -out privateKey.pem
openssl ec -in privateKey.pem -pubout -out publicKey.pem
```

Create a message.txt file and sign it:

```
openssl dgst -sha256 -sign privateKey.pem -out signatureDer.txt message.txt
```

It's time to verify:

```ruby
require 'starkbank-ecdsa'

publicKeyPem = EllipticCurve::Utils::File.read("publicKey.pem")
signatureDer = EllipticCurve::Utils::File.read("signatureDer.txt", "binary")
message = EllipticCurve::Utils::File.read("message.txt")

publicKey = PublicKey.fromPem(publicKeyPem)
signature = Signature.fromDer(signatureDer)

puts Ecdsa.verify(message, signature, publicKey)
```

You can also verify it on terminal:

```
openssl dgst -sha256 -verify publicKey.pem -signature signatureDer.txt message.txt
```

NOTE: If you want to create a Digital Signature to use in the [Stark Bank], you need to convert the binary signature to base64.

```
openssl base64 -in signatureDer.txt -out signatureBase64.txt
```

With this library, you can do it:

```ruby
require 'starkbank-ecdsa'

signatureDer = EllipticCurve::Utils::File.read("test/signatureDer.txt", "binary")

signature = EllipticCurve::Signature.fromDer(signatureDer)

puts signature.toBase64()
```

### Developing the gem

Clone the repository and install the dependencies:

```
git clone https://github.com/starkbank/ecdsa-ruby.git
bundle install
```

### Run all unit tests

```
rake test
```

[Stark Bank]: https://starkbank.com
