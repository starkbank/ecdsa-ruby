module EllipticCurve
    module Utils
        class Der
            module DerFieldType
                @integer = "integer"
                @bitString = "bitString"
                @octetString = "octetString"
                @null = "null"
                @object = "object"
                @printableString = "printableString"
                @utcTime = "utcTime"
                @sequence = "sequence"
                @set = "set"
                @oidContainer = "oidContainer"
                @publicKeyPointContainer = "publicKeyPointContainer"

                class << self; attr_accessor :integer, :bitString, :octetString, :null, :object, :printableString, :utcTime, :sequence, :set, :oidContainer, :publicKeyPointContainer; end
            end

            @_hexTagToType = {
                "02" => DerFieldType.integer,
                "03" => DerFieldType.bitString,
                "04" => DerFieldType.octetString,
                "05" => DerFieldType.null,
                "06" => DerFieldType.object,
                "13" => DerFieldType.printableString,
                "17" => DerFieldType.utcTime,
                "30" => DerFieldType.sequence,
                "31" => DerFieldType.set,
                "a0" => DerFieldType.oidContainer,
                "a1" => DerFieldType.publicKeyPointContainer
            }

            @_typeToHexTag = {}
            
            @_hexTagToType.each { |k, v| @_typeToHexTag[v] = k }

            def self.encodeConstructed(*encodedValues)
                return self.encodePrimitive(DerFieldType.sequence, encodedValues.join(""))
            end

            def self.encodePrimitive(tagType, value)
                if tagType == DerFieldType.integer
                    value = self._encodeInteger(value)
                end
                if tagType == DerFieldType.object
                    value = Utils::Oid.oidToHex(value)
                end
                return "#{@_typeToHexTag[tagType]}#{self._generateLengthBytes(value)}#{value}"
            end

            def self.parse(hexadecimal)
                if hexadecimal.class == String && hexadecimal.empty?
                    return []
                elsif not hexadecimal then 
                    return [] 
                end
                
                typeByte, hexadecimal = hexadecimal[0..1], hexadecimal[2..-1]
                length, lengthBytes = self._readLengthBytes(hexadecimal)
                content = hexadecimal[lengthBytes..lengthBytes + length - 1] 
                hexadecimal = hexadecimal[lengthBytes + length..-1]

                if content.length < length
                    raise Exception.new("missing bytes in DER parsing")
                end

                tagData = self._getTagData(typeByte)
                if tagData[:isConstructed]
                    content = self.parse(content)
                end

                valueParser = {
                    DerFieldType.null => lambda { |content| self._parseNull(content) },
                    DerFieldType.object => lambda { |content| self._parseOid(content) },
                    DerFieldType.utcTime => lambda { |content| self._parseTime(content) },
                    DerFieldType.integer => lambda { |content| self._parseInteger(content) },
                    DerFieldType.printableString => lambda { |content| self._parseString(content) },
                }.fetch(tagData[:type], lambda { |content| self._parseAny(content) })

                return [valueParser.call(content)] + self.parse(hexadecimal)
            end

            def self._parseAny(hexadecimal)
                return hexadecimal
            end

            def self._parseOid(hexadecimal)
                return Utils::Oid.oidFromHex(hexadecimal)
            end

            def self._parseTime(hexadecimal)
                string = self._parseString(hexadecimal)
                return DateTime.strptime(string, "%y%m%d%H%M%SZ")
            end

            def self._parseString(hexadecimal)
                return Utils::Binary.byteStringFromHex(hexadecimal)
            end

            def self._parseNull(_content)
                return nil
            end

            def self._parseInteger(hexadecimal)
                integer = Utils::Binary.intFromHex(hexadecimal)
                bits = Utils::Binary.bitsFromHex(hexadecimal[0])
                if bits[0] == "0" # negative numbers are encoded using two's complement
                    return integer
                end
                bitCount = 4 * hexadecimal.length
                return integer - (2 ** bitCount)
            end

            def self._encodeInteger(number)
                hexadecimal = Utils::Binary.hexFromInt(number.abs)
                if number < 0
                    bitCount = hexadecimal.length * 4
                    twosComplement = (2 ** bitCount) + number
                    return Utils::Binary.hexFromInt(twosComplement)
                end
                bits = Utils::Binary.bitsFromHex(hexadecimal[0])
                if bits[0] == "1"
                    hexadecimal = "00" + hexadecimal
                end
                return hexadecimal
            end

            def self._readLengthBytes(hexadecimal)
                lengthBytes = 2
                lengthIndicator = Utils::Binary.intFromHex(hexadecimal[0, lengthBytes])
                isShortForm = lengthIndicator < 128  # checks if first bit of byte is 1 (a.k.a. short-form)
                if isShortForm
                    length = lengthIndicator * 2
                    return length, lengthBytes
                end

                lengthLength = lengthIndicator - 128  # nullifies first bit of byte (only used as long-form flag)
                if lengthLength == 0
                    raise Exception.new("indefinite length encoding located in DER")
                end
                lengthBytes += 2 * lengthLength
                length = Utils::Binary.intFromHex(hexadecimal[2, lengthBytes]) * 2
                return length, lengthBytes
            end

            def self._generateLengthBytes(hexadecimal)
                size = hexadecimal.length.div(2)
                length = Utils::Binary.hexFromInt(size)
                if size < 128
                    return length.rjust(2, "0")
                end
                lengthLength = 128 + length.length.div(2)
                return Utils::Binary.hexFromInt(lengthLength) + length
            end

            def self._getTagData(tag)
                bits = Utils::Binary.bitsFromHex(tag)
                bit8 = bits[0]
                bit7 = bits[1]
                bit6 = bits[2]

                tagClass = {
                    "0" => {
                        "0" => "universal",
                        "1" => "application",
                    },
                    "1" => {
                        "0" => "context-specific",
                        "1" => "private",
                    },
                }[bit8][bit7]
                
                isConstructed = bit6 == "1"

                return {
                    "class": tagClass,
                    "isConstructed": isConstructed,
                    "type": @_hexTagToType[tag],
                }
            end
        end
    end
end
