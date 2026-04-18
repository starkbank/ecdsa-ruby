require('securerandom')
require('openssl')

module EllipticCurve
    module Utils
        class RandomInteger
            # Return integer x in the range: min <= x <= max
            #
            # Parameters (required):
            # :param min: minimum value of the integer
            # :param max: maximum value of the integer
            # :return: A random number between min and max
            def self.between(min, max)
                if (max - min) < 0 then
                    raise Exception.new("max must be greater than min")
                end
                if (max - min) > 0 then
                    return SecureRandom.random_number((max + 1) - min) + min
                end
                return min
            end

            def self.rfc6979(hashBytes, secret, curve, hashfunc)
                # Generate nonce values per hedged RFC 6979: deterministic k derivation
                # with fresh random entropy mixed into K-init (RFC 6979 §3.6). Same message
                # and key yield different signatures, while preserving RFC 6979's protection
                # against RNG failures.
                orderBitLen = curve.n.bit_length
                orderByteLen = (orderBitLen + 7) / 8

                secretHex = Binary.hexFromInt(secret).rjust(orderByteLen * 2, "0")
                secretBytes = Binary.byteStringFromHex(secretHex)

                hashReduced = Binary.numberFromByteString(hashBytes, orderBitLen) % curve.n
                hashHex = Binary.hexFromInt(hashReduced).rjust(orderByteLen * 2, "0")
                hashOctets = Binary.byteStringFromHex(hashHex)

                extraEntropyHex = Binary.hexFromInt(between(0, (1 << (orderByteLen * 8)) - 1)).rjust(orderByteLen * 2, "0")
                extraEntropy = Binary.byteStringFromHex(extraEntropyHex)

                hLen = hashfunc.call("").bytesize
                digestName = _digestNameFromLength(hLen)
                v = "\x01".b * hLen
                k = "\x00".b * hLen

                k = OpenSSL::HMAC.digest(digestName, k, v + "\x00".b + secretBytes + hashOctets + extraEntropy)
                v = OpenSSL::HMAC.digest(digestName, k, v)
                k = OpenSSL::HMAC.digest(digestName, k, v + "\x01".b + secretBytes + hashOctets + extraEntropy)
                v = OpenSSL::HMAC.digest(digestName, k, v)

                Enumerator.new do |yielder|
                    loop do
                        t = "".b
                        while t.bytesize * 8 < orderBitLen
                            v = OpenSSL::HMAC.digest(digestName, k, v)
                            t += v
                        end

                        kCandidate = Binary.numberFromByteString(t, orderBitLen)

                        if kCandidate >= 1 && kCandidate <= curve.n - 1
                            yielder.yield kCandidate
                        end

                        k = OpenSSL::HMAC.digest(digestName, k, v + "\x00".b)
                        v = OpenSSL::HMAC.digest(digestName, k, v)
                    end
                end
            end

            private

            def self._digestNameFromLength(hLen)
                case hLen
                when 32
                    "SHA256"
                when 48
                    "SHA384"
                when 64
                    "SHA512"
                when 20
                    "SHA1"
                else
                    "SHA256"
                end
            end
        end
    end
end
