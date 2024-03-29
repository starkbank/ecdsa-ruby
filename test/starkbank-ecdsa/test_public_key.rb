require_relative '../test_helper'

describe EllipticCurve::PublicKey do
  it 'converts to and from Pem' do
    privateKey = EllipticCurve::PrivateKey.new()
    publicKey1 = privateKey.publicKey()
    pem = publicKey1.toPem()
    publicKey2 = EllipticCurve::PublicKey.fromPem(pem)
    expect(publicKey1.point.x).must_equal publicKey2.point.x
    expect(publicKey1.point.y).must_equal publicKey2.point.y
    expect(publicKey1.curve).must_equal publicKey2.curve
  end
  
  it 'converts to and from Der' do
    privateKey = EllipticCurve::PrivateKey.new()
    publicKey1 = privateKey.publicKey()
    der = publicKey1.toDer()
    publicKey2 = EllipticCurve::PublicKey.fromDer(der)
    expect(publicKey1.point.x).must_equal publicKey2.point.x
    expect(publicKey1.point.y).must_equal publicKey2.point.y
    expect(publicKey1.curve).must_equal publicKey2.curve
  end
  
  it 'converts to and from a string' do
    privateKey = EllipticCurve::PrivateKey.new()
    publicKey1 = privateKey.publicKey()
    string = publicKey1.toString()
    publicKey2 = EllipticCurve::PublicKey.fromString(string)
    expect(publicKey1.point.x).must_equal publicKey2.point.x
    expect(publicKey1.point.y).must_equal publicKey2.point.y
    expect(publicKey1.curve).must_equal publicKey2.curve
  end
end
