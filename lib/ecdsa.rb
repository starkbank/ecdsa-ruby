require 'digest'


module EllipticCurve
    module Ecdsa
        def self.sign(message, privateKey, hashfunc=nil)
            if hashfunc.nil? then hashfunc = lambda{ |x| Digest::SHA256.digest(x) } end
            curve = privateKey.curve
            byteMessage = hashfunc.call(message)
            numberMessage = Utils::Binary.numberFromByteString(byteMessage, curve.n.bit_length)

            r, s, randSignPoint = 0, 0, nil
            kIterator = Utils::RandomInteger.rfc6979(byteMessage, privateKey.secret, curve, hashfunc)
            while r == 0 or s == 0
                randNum = kIterator.next
                randSignPoint = Math.multiply(curve.g, randNum, curve.n, curve.a, curve.p)
                r = randSignPoint.x % curve.n
                s = ((numberMessage + r * privateKey.secret) * (Math.inv(randNum, curve.n))) % curve.n
            end
            recoveryId = randSignPoint.y & 1
            if randSignPoint.y > curve.n
                recoveryId += 2
            end
            if s > curve.n / 2
                s = curve.n - s
                recoveryId ^= 1
            end

            return Signature.new(r, s, recoveryId)
        end

        def self.verify(message, signature, publicKey, hashfunc=nil)
            if hashfunc.nil? then hashfunc = lambda{ |x| Digest::SHA256.digest(x) } end
            curve = publicKey.curve
            byteMessage = hashfunc.call(message)
            numberMessage = Utils::Binary.numberFromByteString(byteMessage, curve.n.bit_length)

            r = signature.r
            s = signature.s

            if not (1 <= r and r <= curve.n - 1)
                return false
            end
            if not (1 <= s and s <= curve.n - 1)
                return false
            end
            if not curve.contains(publicKey.point)
                return false
            end
            inv = Math.inv(s, curve.n)
            v = Math.multiplyAndAdd(
                curve.g, (numberMessage * inv) % curve.n,
                publicKey.point, (r * inv) % curve.n,
                curve.n, curve.a, curve.p,
            )
            if v.isAtInfinity
                return false
            end
            return v.x % curve.n == r
        end
    end
end
