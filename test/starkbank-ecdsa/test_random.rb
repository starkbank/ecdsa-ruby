describe EllipticCurve::PublicKey do
    it 'test many' do
        for _ in 0..100
            privateKey1 = EllipticCurve::PrivateKey.new()
            publicKey1 = privateKey1.publicKey()

            privateKeyPem = privateKey1.toPem
            publicKeyPem = publicKey1.toPem

            privateKey2 = EllipticCurve::PrivateKey.fromPem(privateKeyPem)
            publicKey2 = EllipticCurve::PublicKey.fromPem(publicKeyPem)

            message = 'test'

            signatureBase64 = EllipticCurve::Ecdsa.sign(message, privateKey2).toBase64()
            signature = EllipticCurve::Signature.fromBase64(signatureBase64)

            expect(EllipticCurve::Ecdsa.verify(message, signature, publicKey2)).must_equal true
        end
    end
end
