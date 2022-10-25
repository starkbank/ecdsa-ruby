module EllipticCurve
    module Utils
        class Oid
            def self.oidFromHex(hexadecimal)
                firstByte, remainingBytes = hexadecimal[0..1], hexadecimal[2..-1]
                firstByteInt = Utils::Binary.intFromHex(firstByte)
                oid = [firstByteInt.div(40), firstByteInt % 40]
                oidInt = 0
                while remainingBytes.to_s.length > 0
                    byte, remainingBytes = remainingBytes[0..1], remainingBytes[2..-1]
                    byteInt = Utils::Binary.intFromHex(byte)
                    if byteInt >= 128
                        oidInt = (128 * oidInt) + (byteInt - 128)
                        next
                    end
                    oidInt = (128 * oidInt) + byteInt
                    oid.append(oidInt)
                    oidInt = 0
                end
                return oid
            end

            def self.oidToHex(oid)
                hexadecimal = Utils::Binary.hexFromInt(40 * oid[0] + oid[1])
                for number in oid[2..-1]
                    hexadecimal += self._oidNumberToHex(number)
                end
                return hexadecimal
            end

            def self._oidNumberToHex(number)
                hexadecimal = ""
                endDelta = 0
                while number > 0
                    hexadecimal = Utils::Binary.hexFromInt((number % 128) + endDelta) + hexadecimal
                    number = number.div(128)
                    endDelta = 128
                end
                return hexadecimal == "" ? "00" : hexadecimal
            end
        end
    end
end
