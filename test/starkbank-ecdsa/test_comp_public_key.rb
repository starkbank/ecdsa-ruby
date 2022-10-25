require_relative '../test_helper'

describe EllipticCurve::PublicKey do
  it 'test in batch' do
    (0..1000).each do
      privateKey = EllipticCurve::PrivateKey.new()
      publicKey = privateKey.publicKey()
      privateKeyString = publicKey.toCompressed()

      recoveredPublicKey = EllipticCurve::PublicKey.fromCompressed(privateKeyString)

      expect(publicKey.point.x).must_equal recoveredPublicKey.point.x
      expect(publicKey.point.y).must_equal recoveredPublicKey.point.y
    end
  end
  
  it 'test even fromCompressed' do
    publicKeyCompressed = "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2"
    publicKey = EllipticCurve::PublicKey.fromCompressed(publicKeyCompressed)
    expect(publicKey.toPem).must_equal "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\nsJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n-----END PUBLIC KEY-----"
  end

  it 'test odd fromCompressed' do
    publicKeyCompressed = "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50"
    publicKey = EllipticCurve::PublicKey.fromCompressed(publicKeyCompressed)
    expect(publicKey.toPem).must_equal "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n-----END PUBLIC KEY-----"
  end

  it 'test even toCompressed' do
    publicKey = EllipticCurve::PublicKey.fromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\nsJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n-----END PUBLIC KEY-----")
    expect(publicKey.toCompressed).must_equal "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2"
  end

  it 'test odd toCompressed' do
    publicKey = EllipticCurve::PublicKey.fromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n-----END PUBLIC KEY-----")
    expect(publicKey.toCompressed).must_equal "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50"
  end

end
