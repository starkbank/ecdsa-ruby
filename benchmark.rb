require_relative 'lib/starkbank-ecdsa'

ROUNDS = 100

def benchmark()
    privateKey = EllipticCurve::PrivateKey.new()
    publicKey = privateKey.publicKey()
    message = "This is a benchmark test message"

    # Warmup
    sig = EllipticCurve::Ecdsa.sign(message, privateKey)
    EllipticCurve::Ecdsa.verify(message, sig, publicKey)

    # Benchmark sign
    start = Time.now
    ROUNDS.times do
        sig = EllipticCurve::Ecdsa.sign(message, privateKey)
    end
    signTime = (Time.now - start) / ROUNDS * 1000

    # Benchmark verify
    start = Time.now
    ROUNDS.times do
        EllipticCurve::Ecdsa.verify(message, sig, publicKey)
    end
    verifyTime = (Time.now - start) / ROUNDS * 1000

    puts ""
    puts "starkbank-ecdsa benchmark (#{ROUNDS} rounds)"
    puts "---------------------------------------"
    puts "sign:    #{format('%.1f', signTime)}ms"
    puts "verify:  #{format('%.1f', verifyTime)}ms"
    puts ""
end

benchmark()
