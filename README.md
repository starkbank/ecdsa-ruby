## A lightweight and fast ECDSA implementation

### Overview

This is a Ruby implementation of the Elliptic Curve Digital Signature Algorithm. It is compatible with OpenSSL and uses elegant math such as Jacobian Coordinates to speed up the ECDSA on pure Ruby.

### Installation

To install StarkBank`s ECDSA-Ruby, run:

```sh
gem install starkbank-ecdsa
```

### Curves

We currently support `secp256k1`, but you can add more curves to your project. You just need to use the `EllipticCurve::Curve.add()` method.

### Speed

We ran a test on Ruby 2.6.8 on a MAC Air M1 2020. The library ran 100 times and showed the average times displayed bellow:

| Library            | sign          | verify  |
| ------------------ |:-------------:| -------:|
| starkbank-ecdsa    |     3.4ms     | 6.6ms  |

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

How to add more curves:

```ruby
require 'starkbank-ecdsa'

newCurve = EllipticCurve::Curve::CurveFp.new(
    0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00,
    0xee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f,
    0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03,
    0xf1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1,
    0xb6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff,
    0x6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb,
    "frp256v1",
    [1, 2, 250, 1, 223, 101, 256, 1]
)

EllipticCurve::Curve.add(newCurve)

publicKeyPem = "-----BEGIN PUBLIC KEY-----\nMFswFQYHKoZIzj0CAQYKKoF6AYFfZYIAAQNCAATeEFFYiQL+HmDYTf+QDmvQmWGD\ndRJPqLj11do8okvkSxq2lwB6Ct4aITMlCyg3f1msafc/ROSN/Vgj69bDhZK6\n-----END PUBLIC KEY-----"

publicKey = EllipticCurve::PublicKey.fromPem(publicKeyPem)

puts publicKey.toPem
```

How to generate a compressed public key:

```ruby
require 'starkbank-ecdsa'

privateKey = EllipticCurve::PrivateKey.new()
publicKey = privateKey.publicKey()
compressedPublicKey = publicKey.toCompressed()

puts compressedPublicKey
```

How to recover a compressed public key:

```ruby
require 'starkbank-ecdsa'

compressedPublicKey = "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2"
publicKey = EllipticCurve::PublicKey.fromCompressed(compressedPublicKey)

puts publicKey.toPem()
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
