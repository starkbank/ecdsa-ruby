module EllipticCurve
    class Signature
        attr_reader :r, :s, :recoveryId
        
        def initialize(r, s, recoveryId=nil)
            @r = r
            @s = s
            @recoveryId = recoveryId
        end

        def toDer(withRecoveryId=false)
            hexadecimal = self._toString
            encodedSequence = Utils::Binary.byteStringFromHex(hexadecimal)
            if not withRecoveryId
                return encodedSequence
            end
            return (27 + @recoveryId).chr + encodedSequence
        end

        def toBase64(withRecoveryId=false)
            return Utils::Binary.base64FromByteString(self.toDer(withRecoveryId))
        end

        def self.fromDer(string, recoveryByte=false)
            @recoveryId = nil
            if recoveryByte
                @recoveryId = string[0].ord - 27
                string = string[1..-1]
            end
            hexadecimal = Utils::Binary.hexFromByteString(string)
            return self._fromString(hexadecimal, @recoveryId)
        end

        def self.fromBase64(string, recoveryByte=false)
            der = Utils::Binary.byteStringFromBase64(string)
            return self.fromDer(der, recoveryByte)
        end

        def _toString
            return Utils::Der.encodeConstructed(
                Utils::Der.encodePrimitive(Utils::Der::DerFieldType.integer, @r),
                Utils::Der.encodePrimitive(Utils::Der::DerFieldType.integer, @s)
            )
        end

        def self._fromString(string, recoveryId=nil)
            @r, @s = Utils::Der.parse(string)[0]
            return Signature.new(@r, @s, recoveryId)
        end
    end
end
