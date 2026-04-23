module EllipticCurve
    #
    # Elliptic Curve Equation
    #
    # y^2 = x^3 + A*x + B (mod P)
    #
    module Curve
        class CurveFp
            attr_accessor :a, :b, :p, :n, :g, :name, :oid, :nistName, :nBitLength, :glvParams
            attr_accessor :_generatorPowersTable

            def initialize(a, b, p, n, gx, gy, name, oid, nistName=nil, glvParams=nil)
                @a = a
                @b = b
                @p = p
                @n = n
                @nBitLength = n.bit_length
                @g = Point.new(gx, gy)
                @name = name
                @oid = oid
                @nistName = nistName
                # GLV endomorphism parameters (only for curves that support one,
                # e.g. secp256k1). nil means no endomorphism; fall back to Shamir+JSF.
                @glvParams = glvParams
                @_generatorPowersTable = nil
            end
            
            def contains(p)
                # Verify if the point `p` is on the curve
                # :param p: point p = Point(x, y)
                # :return: boolean
                if not (0 <= p.x and p.x <= @p - 1)
                    return false
                end
                if not (0 <= p.y and p.y <= @p - 1)
                    return false
                end
                if (p.y ** 2 - (p.x ** 3 + @a * p.x + @b)) % @p != 0
                    return false
                end
                return true
            end

            def length
                return (1 + ("%x" % @n).length).div(2)
            end

            def y(x, isEven)
                ySquared = (x.pow(3, @p) + @a * x + @b) % @p
                y = Math::modularSquareRoot(ySquared, @p)
                if isEven != (y % 2 == 0)
                    y = @p - y
                end
                return y
            end

        end

        @_curvesByOid = { }

        def self.add(curve)
            @_curvesByOid[curve.oid] = curve
        end

        def self.getbyOid(oid)
            if not @_curvesByOid.include?(oid)
                raise Exception.new("Unknown curve oid: #{oid}; The following are registered: #{@_curvesByOid.map{|k,v| v.name}}")
            end
            return @_curvesByOid[oid]
        end

        SECP256K1 = CurveFp.new(
            0x0000000000000000000000000000000000000000000000000000000000000000,
            0x0000000000000000000000000000000000000000000000000000000000000007,
            0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
            0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
            0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
            0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
            "secp256k1",
            [1, 3, 132, 0, 10],
            nil,
            # GLV endomorphism phi((x,y)) = (beta*x, y), equivalent to lambda*P.
            # Basis vectors from Gauss reduction; used to split a 256-bit scalar k
            # into two ~128-bit scalars (k1, k2) with k == k1 + k2*lambda (mod N).
            {
                :beta   => 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee,
                :lambda => 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72,
                :a1     => 0x3086d221a7d46bcde86c90e49284eb15,
                :b1     => -0xe4437ed6010e88286f547fa90abfe4c3,
                :a2     => 0x114ca50f7a8e2f3f657c1108d9d44cfd8,
                :b2     => 0x3086d221a7d46bcde86c90e49284eb15,
            }
        )

        PRIME256V1 = CurveFp.new(
            0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
            0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
            0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
            0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
            0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
            0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
            "prime256v1",
            [1, 2, 840, 10045, 3, 1, 7],
            "p-256",
        )

        P256 = PRIME256V1

        self.add(PRIME256V1)
        self.add(SECP256K1)
    end
end
