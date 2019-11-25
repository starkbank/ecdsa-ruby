require 'digest'
require 'openssl'
require 'signature'


module Ecdsa

    def self.sign(message, privateKey, hashfunc=nil)
        if hashfunc.nil?
            message = Digest::SHA256.digest(message)
        else
            message = hashfunc(message)
        end
        
        signature = privateKey.openSslPrivateKey.dsa_sign_asn1(message)
        signature = Signature.new(signature)
        return signature
    end

    def self.verify(message, signature, publicKey, hashfunc=nil)
        if hashfunc.nil?
            message = Digest::SHA256.digest(message)
        else
            message = hashfunc(message)
        end
        return publicKey.openSslPublicKey.dsa_verify_asn1(message, signature.toDer())
    end
end