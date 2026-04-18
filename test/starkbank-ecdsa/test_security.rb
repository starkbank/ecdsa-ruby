require_relative '../test_helper'
require 'digest'

describe 'Prime256v1PublicKeyDerivationTest' do
    # RFC 6979 A.2.5 public key derivation. Signatures are hedged, so r/s
    # no longer match fixed test vectors, but pubkey derivation is unchanged.

    before do
        @privateKey = EllipticCurve::PrivateKey.new(
            EllipticCurve::Curve::PRIME256V1,
            0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721,
        )
        @publicKey = @privateKey.publicKey()
    end

    it 'testPublicKeyMatchesRfc' do
        expect(@publicKey.point.x).must_equal 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
        expect(@publicKey.point.y).must_equal 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
    end

    it 'testSampleMessageRoundTrip' do
        sig = EllipticCurve::Ecdsa.sign("sample", @privateKey)
        expect(sig.s <= EllipticCurve::Curve::PRIME256V1.n / 2).must_equal true
        expect(EllipticCurve::Ecdsa.verify("sample", sig, @publicKey)).must_equal true
    end

    it 'testTestMessageRoundTrip' do
        sig = EllipticCurve::Ecdsa.sign("test", @privateKey)
        expect(sig.s <= EllipticCurve::Curve::PRIME256V1.n / 2).must_equal true
        expect(EllipticCurve::Ecdsa.verify("test", sig, @publicKey)).must_equal true
    end
end

describe 'Secp256k1PublicKeyDerivationTest' do
    # secp256k1 with secret=1 (pubkey = generator G).

    before do
        @privateKey = EllipticCurve::PrivateKey.new(EllipticCurve::Curve::SECP256K1, 1)
        @publicKey = @privateKey.publicKey()
    end

    it 'testPublicKeyIsGenerator' do
        expect(@publicKey.point.x).must_equal EllipticCurve::Curve::SECP256K1.g.x
        expect(@publicKey.point.y).must_equal EllipticCurve::Curve::SECP256K1.g.y
    end

    it 'testSampleMessageRoundTrip' do
        sig = EllipticCurve::Ecdsa.sign("sample", @privateKey)
        expect(EllipticCurve::Ecdsa.verify("sample", sig, @publicKey)).must_equal true
    end

    it 'testTestMessageRoundTrip' do
        sig = EllipticCurve::Ecdsa.sign("test", @privateKey)
        expect(EllipticCurve::Ecdsa.verify("test", sig, @publicKey)).must_equal true
    end
end

describe 'MalleabilityTest' do
    it 'testSignAlwaysProducesLowS' do
        100.times do
            privateKey = EllipticCurve::PrivateKey.new()
            signature = EllipticCurve::Ecdsa.sign("test message", privateKey)
            expect(signature.s <= privateKey.curve.n / 2).must_equal true
        end
    end

    it 'testHighSSignatureStillVerifies' do
        # verify() accepts high-s for OpenSSL compatibility; sign() prevents malleability
        privateKey = EllipticCurve::PrivateKey.new()
        publicKey = privateKey.publicKey()
        message = "test message"

        signature = EllipticCurve::Ecdsa.sign(message, privateKey)
        highS = EllipticCurve::Signature.new(signature.r, privateKey.curve.n - signature.s)

        expect(EllipticCurve::Ecdsa.verify(message, signature, publicKey)).must_equal true
        expect(EllipticCurve::Ecdsa.verify(message, highS, publicKey)).must_equal true
    end
end

describe 'PublicKeyValidationTest' do
    it 'testRejectOffCurvePublicKey' do
        privateKey = EllipticCurve::PrivateKey.new()
        publicKey = privateKey.publicKey()
        message = "test message"

        signature = EllipticCurve::Ecdsa.sign(message, privateKey)

        offCurvePoint = EllipticCurve::Point.new(publicKey.point.x, publicKey.point.y + 1)
        offCurveKey = EllipticCurve::PublicKey.new(offCurvePoint, publicKey.curve)

        expect(EllipticCurve::Ecdsa.verify(message, signature, offCurveKey)).must_equal false
    end

    it 'testFromStringRejectsOffCurvePoint' do
        p = EllipticCurve::PrivateKey.new().publicKey()
        badY = EllipticCurve::Utils::Binary.hexFromInt(p.point.y + 1).rjust(2 * p.curve.length, "0")
        badHex = EllipticCurve::Utils::Binary.hexFromInt(p.point.x).rjust(2 * p.curve.length, "0") + badY
        expect {
            EllipticCurve::PublicKey.fromString(badHex, p.curve)
        }.must_raise Exception
    end

    it 'testFromStringRejectsInfinityPoint' do
        zeroHex = "00" * (2 * EllipticCurve::Curve::SECP256K1.length)
        expect {
            EllipticCurve::PublicKey.fromString(zeroHex, EllipticCurve::Curve::SECP256K1)
        }.must_raise Exception
    end
end

describe 'ForgeryAttemptTest' do
    before do
        @privateKey = EllipticCurve::PrivateKey.new()
        @publicKey = @privateKey.publicKey()
        @message = "authentic message"
        @signature = EllipticCurve::Ecdsa.sign(@message, @privateKey)
    end

    it 'testRejectZeroSignature' do
        expect(EllipticCurve::Ecdsa.verify(@message, EllipticCurve::Signature.new(0, 0), @publicKey)).must_equal false
    end

    it 'testRejectREqualsZero' do
        expect(EllipticCurve::Ecdsa.verify(@message, EllipticCurve::Signature.new(0, @signature.s), @publicKey)).must_equal false
    end

    it 'testRejectSEqualsZero' do
        expect(EllipticCurve::Ecdsa.verify(@message, EllipticCurve::Signature.new(@signature.r, 0), @publicKey)).must_equal false
    end

    it 'testRejectREqualsN' do
        n = @publicKey.curve.n
        expect(EllipticCurve::Ecdsa.verify(@message, EllipticCurve::Signature.new(n, @signature.s), @publicKey)).must_equal false
    end

    it 'testRejectSEqualsN' do
        n = @publicKey.curve.n
        expect(EllipticCurve::Ecdsa.verify(@message, EllipticCurve::Signature.new(@signature.r, n), @publicKey)).must_equal false
    end

    it 'testRejectRExceedsN' do
        n = @publicKey.curve.n
        expect(EllipticCurve::Ecdsa.verify(@message, EllipticCurve::Signature.new(n + 1, @signature.s), @publicKey)).must_equal false
    end

    it 'testRejectArbitrarySignature' do
        expect(EllipticCurve::Ecdsa.verify(@message, EllipticCurve::Signature.new(1, 1), @publicKey)).must_equal false
    end

    it 'testRejectBoundarySignature' do
        n = @publicKey.curve.n
        expect(EllipticCurve::Ecdsa.verify(@message, EllipticCurve::Signature.new(n - 1, n - 1), @publicKey)).must_equal false
    end

    it 'testWrongKeyRejected' do
        otherKey = EllipticCurve::PrivateKey.new().publicKey()
        expect(EllipticCurve::Ecdsa.verify(@message, @signature, otherKey)).must_equal false
    end
end

describe 'HedgedSignatureTest' do
    it 'testSameInputsProduceDifferentSignatures' do
        privateKey = EllipticCurve::PrivateKey.new()
        message = "test message"

        signature1 = EllipticCurve::Ecdsa.sign(message, privateKey)
        signature2 = EllipticCurve::Ecdsa.sign(message, privateKey)

        expect(signature1.r != signature2.r || signature1.s != signature2.s).must_equal true
    end

    it 'testDifferentMessagesDifferentSignatures' do
        privateKey = EllipticCurve::PrivateKey.new()

        signature1 = EllipticCurve::Ecdsa.sign("message 1", privateKey)
        signature2 = EllipticCurve::Ecdsa.sign("message 2", privateKey)

        expect(signature1.r != signature2.r || signature1.s != signature2.s).must_equal true
    end

    it 'testDifferentKeysDifferentSignatures' do
        message = "test message"

        signature1 = EllipticCurve::Ecdsa.sign(message, EllipticCurve::PrivateKey.new())
        signature2 = EllipticCurve::Ecdsa.sign(message, EllipticCurve::PrivateKey.new())

        expect(signature1.r != signature2.r || signature1.s != signature2.s).must_equal true
    end
end

describe 'EdgeCaseMessageTest' do
    before do
        @privateKey = EllipticCurve::PrivateKey.new()
        @publicKey = @privateKey.publicKey()
    end

    def _signAndVerify(message)
        sig = EllipticCurve::Ecdsa.sign(message, @privateKey)
        expect(EllipticCurve::Ecdsa.verify(message, sig, @publicKey)).must_equal true
        expect(EllipticCurve::Ecdsa.verify(message + "x", sig, @publicKey)).must_equal false
    end

    it 'testEmptyMessage' do
        _signAndVerify("")
    end

    it 'testSingleCharMessage' do
        _signAndVerify("a")
    end

    it 'testUnicodeMessage' do
        _signAndVerify("\u00e9\u00e8\u00ea\u00eb")
    end

    it 'testEmojiMessage' do
        _signAndVerify("\u{1f512}\u{1f511}")
    end

    it 'testNullByteMessage' do
        _signAndVerify("before\x00after")
    end

    it 'testLongMessage' do
        _signAndVerify("a" * 10000)
    end

    it 'testNewlinesAndWhitespace' do
        _signAndVerify("  line1\n\tline2\r\n  ")
    end
end

describe 'SerializationRoundTripTest' do
    before do
        @privateKey = EllipticCurve::PrivateKey.new()
        @publicKey = @privateKey.publicKey()
        @message = "round-trip test"
        @signature = EllipticCurve::Ecdsa.sign(@message, @privateKey)
    end

    it 'testSignatureDerRoundTrip' do
        der = @signature.toDer()
        restored = EllipticCurve::Signature.fromDer(der)
        expect(restored.r).must_equal @signature.r
        expect(restored.s).must_equal @signature.s
        expect(EllipticCurve::Ecdsa.verify(@message, restored, @publicKey)).must_equal true
    end

    it 'testSignatureBase64RoundTrip' do
        b64 = @signature.toBase64()
        restored = EllipticCurve::Signature.fromBase64(b64)
        expect(restored.r).must_equal @signature.r
        expect(restored.s).must_equal @signature.s
        expect(EllipticCurve::Ecdsa.verify(@message, restored, @publicKey)).must_equal true
    end

    it 'testSignatureDerWithRecoveryIdRoundTrip' do
        der = @signature.toDer(true)
        restored = EllipticCurve::Signature.fromDer(der, true)
        expect(restored.r).must_equal @signature.r
        expect(restored.s).must_equal @signature.s
        expect(restored.recoveryId).must_equal @signature.recoveryId
    end

    it 'testPrivateKeyPemRoundTrip' do
        pem = @privateKey.toPem()
        restored = EllipticCurve::PrivateKey.fromPem(pem)
        expect(restored.secret).must_equal @privateKey.secret
        expect(restored.curve.name).must_equal @privateKey.curve.name
    end

    it 'testPrivateKeyDerRoundTrip' do
        der = @privateKey.toDer()
        restored = EllipticCurve::PrivateKey.fromDer(der)
        expect(restored.secret).must_equal @privateKey.secret
    end

    it 'testPublicKeyPemRoundTrip' do
        pem = @publicKey.toPem()
        restored = EllipticCurve::PublicKey.fromPem(pem)
        expect(restored.point.x).must_equal @publicKey.point.x
        expect(restored.point.y).must_equal @publicKey.point.y
    end

    it 'testPublicKeyCompressedRoundTrip' do
        compressed = @publicKey.toCompressed()
        restored = EllipticCurve::PublicKey.fromCompressed(compressed, @publicKey.curve)
        expect(restored.point.x).must_equal @publicKey.point.x
        expect(restored.point.y).must_equal @publicKey.point.y
        expect(EllipticCurve::Ecdsa.verify(@message, @signature, restored)).must_equal true
    end

    it 'testPublicKeyCompressedEvenAndOdd' do
        # Ensure both even-y and odd-y keys round-trip through compression
        20.times do
            pk = EllipticCurve::PrivateKey.new()
            pub = pk.publicKey()
            compressed = pub.toCompressed()
            restored = EllipticCurve::PublicKey.fromCompressed(compressed, pub.curve)
            expect(restored.point.x).must_equal pub.point.x
            expect(restored.point.y).must_equal pub.point.y
        end
    end

    it 'testPrime256v1KeyRoundTrip' do
        pk = EllipticCurve::PrivateKey.new(EllipticCurve::Curve::PRIME256V1)
        pem = pk.toPem()
        restored = EllipticCurve::PrivateKey.fromPem(pem)
        expect(restored.secret).must_equal pk.secret
        expect(restored.curve.name).must_equal "prime256v1"
    end
end

describe 'TonelliShanksTest' do
    it 'testPrimeCongruent1Mod4' do
        # P = 17: 17 - 1 = 16 = 2^4, S = 4, exercises full Tonelli-Shanks
        p = 17
        (1...p).each do |value|
            if value.pow((p - 1) / 2, p) == 1
                root = EllipticCurve::Math.modularSquareRoot(value, p)
                expect((root * root) % p).must_equal value
            end
        end
    end

    it 'testPrimeCongruent5Mod8' do
        # P = 13: 13 - 1 = 12 = 3 * 2^2, S = 2
        p = 13
        (1...p).each do |value|
            if value.pow((p - 1) / 2, p) == 1
                root = EllipticCurve::Math.modularSquareRoot(value, p)
                expect((root * root) % p).must_equal value
            end
        end
    end

    it 'testPrimeCongruent3Mod4' do
        # P = 7: fast path (S = 1)
        p = 7
        (1...p).each do |value|
            if value.pow((p - 1) / 2, p) == 1
                root = EllipticCurve::Math.modularSquareRoot(value, p)
                expect((root * root) % p).must_equal value
            end
        end
    end

    it 'testZeroValue' do
        expect(EllipticCurve::Math.modularSquareRoot(0, 17)).must_equal 0
    end
end

describe 'HashTruncationTest' do
    it 'testSignVerifyWithSha512' do
        privateKey = EllipticCurve::PrivateKey.new()
        publicKey = privateKey.publicKey()
        message = "test message"
        hashfunc = lambda { |x| Digest::SHA512.digest(x) }

        signature = EllipticCurve::Ecdsa.sign(message, privateKey, hashfunc)

        expect(EllipticCurve::Ecdsa.verify(message, signature, publicKey, hashfunc)).must_equal true
        expect(EllipticCurve::Ecdsa.verify("wrong message", signature, publicKey, hashfunc)).must_equal false
    end

    it 'testSha512SignaturesAreHedged' do
        privateKey = EllipticCurve::PrivateKey.new()
        message = "test message"
        hashfunc = lambda { |x| Digest::SHA512.digest(x) }

        signature1 = EllipticCurve::Ecdsa.sign(message, privateKey, hashfunc)
        signature2 = EllipticCurve::Ecdsa.sign(message, privateKey, hashfunc)

        expect(signature1.r != signature2.r || signature1.s != signature2.s).must_equal true
    end

    it 'testHashMismatchFails' do
        privateKey = EllipticCurve::PrivateKey.new()
        publicKey = privateKey.publicKey()
        message = "test message"
        sha256func = lambda { |x| Digest::SHA256.digest(x) }
        sha512func = lambda { |x| Digest::SHA512.digest(x) }

        signature = EllipticCurve::Ecdsa.sign(message, privateKey, sha256func)
        expect(EllipticCurve::Ecdsa.verify(message, signature, publicKey, sha512func)).must_equal false
    end
end

describe 'Prime256v1SecurityTest' do
    it 'testSignVerify' do
        privateKey = EllipticCurve::PrivateKey.new(EllipticCurve::Curve::PRIME256V1)
        publicKey = privateKey.publicKey()
        message = "test message"

        signature = EllipticCurve::Ecdsa.sign(message, privateKey)

        expect(signature.s <= EllipticCurve::Curve::PRIME256V1.n / 2).must_equal true
        expect(EllipticCurve::Ecdsa.verify(message, signature, publicKey)).must_equal true
    end

    it 'testSignaturesAreHedged' do
        privateKey = EllipticCurve::PrivateKey.new(EllipticCurve::Curve::PRIME256V1)
        message = "test message"

        signature1 = EllipticCurve::Ecdsa.sign(message, privateKey)
        signature2 = EllipticCurve::Ecdsa.sign(message, privateKey)

        expect(signature1.r != signature2.r || signature1.s != signature2.s).must_equal true
    end

    it 'testWrongCurveKeyFails' do
        # A signature made with secp256k1 should not verify with a prime256v1 key
        k1Key = EllipticCurve::PrivateKey.new(EllipticCurve::Curve::SECP256K1)
        p256Key = EllipticCurve::PrivateKey.new(EllipticCurve::Curve::PRIME256V1)
        message = "cross-curve test"

        sig = EllipticCurve::Ecdsa.sign(message, k1Key)
        expect(EllipticCurve::Ecdsa.verify(message, sig, p256Key.publicKey())).must_equal false
    end
end
