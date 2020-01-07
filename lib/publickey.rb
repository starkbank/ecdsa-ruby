class PublicKey

    def initialize(openSslPublicKey)
        @openSslPublicKey = openSslPublicKey
    end

    attr_reader :openSslPublicKey

    def toString
        return Base64.encode64(self.toDer())
    end

    def toDer
        @openSslPublicKey.to_der()
    end

    def toPem
        @openSslPublicKey.to_pem()
    end

    def self.fromPem(string)
        return PublicKey.new(OpenSSL::PKey::EC.new(string))
    end

    def self.fromDer(string)
        return PublicKey.new(OpenSSL::PKey::EC.new(string))
    end

    def self.fromString(string)
        return PublicKey.new(OpenSSL::PKey::EC.new(Base64.decode64(string)))
    end

end
