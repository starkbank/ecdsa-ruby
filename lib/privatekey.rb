require "openssl"
require "base64"
require_relative "publickey"


class PrivateKey

    def initialize(curve="secp256k1", openSslKey=nil)
        if openSslKey.nil?
            @openSslPrivateKey = OpenSSL::PKey::EC.new(curve)
            @openSslPrivateKey.generate_key
        else
            @openSslPrivateKey = openSslKey
        end
    end

    attr_reader :openSslPrivateKey

    def publicKey
        dupKey = OpenSSL::PKey::EC.new(@openSslPrivateKey.to_der())
        dupKey.private_key = nil
        return PublicKey.new(dupKey)
    end

    def toString
        return Base64.encode64(self.toDer())
    end

    def toDer
        return @openSslPrivateKey.to_der()
    end

    def toPem
        return @openSslPrivateKey.to_pem()
    end

    def self.fromPem(string)
        return PrivateKey.new(nil, OpenSSL::PKey::EC.new(string))
    end

    def self.fromDer(string)
        return PrivateKey.new(nil, OpenSSL::PKey::EC.new(string))
    end

    def self.fromString(string)
        return PrivateKey.new(nil, OpenSSL::PKey::EC.new(Base64.decode64(string)))
    end

end
