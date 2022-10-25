require "base64"


module EllipticCurve
    module Utils
        class Binary
            def self.hexFromInt(number)
                hexadecimal = number.to_s(16)
                if hexadecimal.length % 2 == 1
                    hexadecimal = "0" + hexadecimal
                end
                return hexadecimal
            end

            def self.intFromHex(hexadecimal)
                return hexadecimal.to_i(16)
            end

            def self.hexFromByteString(bytes)
                return bytes.unpack("H*")[0]
            end

            def self.byteStringFromHex(hexadecimal)
                return [hexadecimal].pack("H*")
            end

            def self.numberFromByteString(bytes)
                return bytes.unpack("C*").reduce(0) { |number, byte| number * 256 + byte }
            end

            def self.base64FromByteString(byteString)
                return Base64.encode64(byteString).gsub("\n", "")
            end

            def self.byteStringFromBase64(base64)
                return Base64.decode64(base64)
            end

            def self.bitsFromHex(hexadecimal)
                return intFromHex(hexadecimal).to_s(2).rjust(hexadecimal.length * 4, "0")
            end
        end
    end
end
