require_relative '../test_helper'

describe EllipticCurve::Ecdsa do
  it 'verifies the right message' do
    privateKey = EllipticCurve::PrivateKey.new()
    publicKey = privateKey.publicKey()
    message = "This is the right message"
    signature = EllipticCurve::Ecdsa.sign(message, privateKey)
    expect(EllipticCurve::Ecdsa.verify(message, signature, publicKey)).must_equal true
  end
  
  it 'will not verify the wrong message' do
    privateKey = EllipticCurve::PrivateKey.new()
    publicKey = privateKey.publicKey()
    message1 = "This is the right message"
    message2 = "This is the wrong message"
    signature = EllipticCurve::Ecdsa.sign(message1, privateKey)
    expect(EllipticCurve::Ecdsa.verify(message2, signature, publicKey)).must_equal false
  end
  
  it 'testZeroSignature' do
    privateKey = EllipticCurve::PrivateKey.new()
    publicKey = privateKey.publicKey()

    message = "This is the wrong message"
    expect(EllipticCurve::Ecdsa.verify(message, EllipticCurve::Signature.new(0, 0), publicKey)).must_equal false
  end
end
