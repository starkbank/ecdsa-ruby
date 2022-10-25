require_relative '../test_helper'

describe EllipticCurve::PrivateKey do
  it 'converts to and from Pem' do
    privateKey1 = EllipticCurve::PrivateKey.new()
    pem = privateKey1.toPem()
    privateKey2 = EllipticCurve::PrivateKey.fromPem(pem)
    expect(privateKey1.secret).must_equal privateKey2.secret
    expect(privateKey1.curve).must_equal privateKey2.curve
  end
  
  it 'converts to and from Der' do
    privateKey1 = EllipticCurve::PrivateKey.new()
    der = privateKey1.toDer()
    privateKey2 = EllipticCurve::PrivateKey.fromDer(der)
    expect(privateKey1.secret).must_equal privateKey2.secret
    expect(privateKey1.curve).must_equal privateKey2.curve
  end
  
  it 'converts to and from a string' do
    privateKey1 = EllipticCurve::PrivateKey.new()
    string = privateKey1.toString()
    privateKey2 = EllipticCurve::PrivateKey.fromString(string)
    expect(privateKey1.secret).must_equal privateKey2.secret
    expect(privateKey1.curve).must_equal privateKey2.curve
  end
end
