require_relative "signature"
require_relative "publickey"
require_relative "privatekey"
require_relative "ecdsa"
require_relative "utils/file"


module EllipticCurve

    Signature = Signature
    PublicKey = PublicKey
    PrivateKey = PrivateKey
    Ecdsa = Ecdsa

    module Utils
        File = File
    end

end
