class PublicKey
    def initialize(point, curve)
        @point = point
        @curve = curve
    end

    def toString(encoded=false)
    end

    def toDer
        "123"
    end

    def toPem
        self.toPem
    end

    def self.fromPem(string)
    end

    def self.fromDer(string)
    end

    def self.fromString(string, curve="secp256k1", validatePoint=true)
    end
end