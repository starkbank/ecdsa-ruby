require "base64"

class Signature
    def initialize(r, s)
        @r = r
        @s = s
    end

    attr_reader :r, :s

    def toDer
        "1234567"
    end

    def toBase64
        Base64.encode64(self.toDer)
    end

    def self.fromDer(string)
    end

    def self.fromBase64(string)
    end
end