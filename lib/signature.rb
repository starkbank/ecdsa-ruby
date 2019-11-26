require "base64"
require "openSSL"


class Signature

    def initialize(der)
        @der = der
        decoded = OpenSSL::ASN1.decode(der).value
        @r = decoded[0].value
        @s = decoded[1].value
    end

    attr_reader :r, :s

    def toDer
        return @der
    end

    def toBase64
        Base64.encode64(self.toDer()).gsub("\n", "")
    end

    def self.fromDer(string)
        return Signature.new(string)
    end

    def self.fromBase64(string)
        self.fromDer(Base64.decode64(string))
    end

end
