require_relative '../test_helper'

describe EllipticCurve::PrivateKey do
    it 'tests assign' do
        # Generated by: openssl ecparam -name secp256k1 -genkey -out privateKey.pem
        privateKeyPem = EllipticCurve::Utils::File.read("test/files/privateKey.pem")

        privateKey = EllipticCurve::PrivateKey.fromPem(privateKeyPem)

        message = EllipticCurve::Utils::File.read("test/files/message.txt")

        signature = EllipticCurve::Ecdsa.sign(message=message, privateKey=privateKey)

        publicKey = privateKey.publicKey()

        expect(EllipticCurve::Ecdsa.verify(message=message, signature=signature, publicKey=publicKey)).must_equal true
    end

    it 'verifies signature' do
        # openssl ec -in privateKey.pem -pubout -out publicKey.pem

        publicKeyPem = EllipticCurve::Utils::File.read("test/files/publicKey.pem")

        # openssl dgst -sha256 -sign privateKey.pem -out signature.binary message.txt
        signatureDer = EllipticCurve::Utils::File.read("test/files/signatureDer.txt")

        message = EllipticCurve::Utils::File.read("test/files/message.txt")

        publicKey = EllipticCurve::PublicKey.fromPem(publicKeyPem)

        signature = EllipticCurve::Signature.fromDer(string=signatureDer)

        expect(EllipticCurve::Ecdsa.verify(message=message, signature=signature, publicKey=publicKey)).must_equal true
    end

end
