module EllipticCurve
    class Math
        def self.modularSquareRoot(value, prime)
            # Tonelli-Shanks algorithm for modular square root. Works for all odd primes.
            if value == 0
                return 0
            end
            if prime == 2
                return value % 2
            end

            # Factor out powers of 2: prime - 1 = Q * 2^S
            q = prime - 1
            s = 0
            while q % 2 == 0
                q /= 2
                s += 1
            end

            if s == 1  # prime = 3 (mod 4)
                return value.pow((prime + 1) / 4, prime)
            end

            # Find a quadratic non-residue z
            z = 2
            while z.pow((prime - 1) / 2, prime) != prime - 1
                z += 1
            end

            m = s
            c = z.pow(q, prime)
            t = value.pow(q, prime)
            r = value.pow((q + 1) / 2, prime)

            while true
                if t == 1
                    return r
                end

                # Find the least i such that t^(2^i) = 1 (mod prime)
                i = 1
                temp = (t * t) % prime
                while temp != 1
                    temp = (temp * temp) % prime
                    i += 1
                end

                b = c.pow(1 << (m - i - 1), prime)
                m = i
                c = (b * b) % prime
                t = (t * c) % prime
                r = (r * b) % prime
            end
        end

        def self.multiplyGenerator(curve, n)
            # Fast scalar multiplication n*G using a precomputed affine table of
            # powers-of-two multiples of G and the width-2 NAF of n. Every non-zero
            # NAF digit triggers one mixed add and zero doublings, trading the ~256
            # doublings of a windowed method for ~86 adds on average - a large net
            # reduction in field multiplications for 256-bit scalars.
            if n < 0 or n >= curve.n
                n = n % curve.n
            end
            if n == 0
                return Point.new(0, 0, 0)
            end

            table = self._generatorPowersTable(curve)
            coeff = curve.a
            prime = curve.p

            r = Point.new(0, 0, 1)
            i = 0
            k = n
            while k > 0
                if (k & 1) != 0
                    digit = 2 - (k & 3)  # -1 or +1
                    k -= digit
                    g = table[i]
                    if digit == 1
                        r = self._jacobianAdd(r, g, coeff, prime)
                    else
                        r = self._jacobianAdd(r, Point.new(g.x, prime - g.y, 1), coeff, prime)
                    end
                end
                k >>= 1
                i += 1
            end
            return self._fromJacobian(r, prime)
        end

        def self._generatorPowersTable(curve)
            # Build [G, 2G, 4G, ..., 2^nBitLength * G] in affine (z=1) form, so each
            # add in multiplyGenerator hits the mixed-add fast path.
            return curve._generatorPowersTable unless curve._generatorPowersTable.nil?
            coeff = curve.a
            prime = curve.p
            current = Point.new(curve.g.x, curve.g.y, 1)
            table = [current]
            # NAF of an nBitLength-bit scalar can be up to nBitLength+1 digits.
            curve.nBitLength.times do
                doubled = self._jacobianDouble(current, coeff, prime)
                if doubled.y == 0
                    current = doubled
                else
                    zInv = self.inv(doubled.z, prime)
                    zInv2 = (zInv * zInv) % prime
                    zInv3 = (zInv2 * zInv) % prime
                    current = Point.new((doubled.x * zInv2) % prime, (doubled.y * zInv3) % prime, 1)
                end
                table << current
            end
            curve._generatorPowersTable = table
            return table
        end

        def self.multiply(p, n, order, coeff, prime)
            # Fast way to multiply point and scalar in elliptic curves
            #
            # :param p: First Point to multiply
            # :param n: Scalar to multiply
            # :param order: Order of the elliptic curve
            # :param coeff: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
            # :param prime: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Point that represents the scalar multiplication
            return self._fromJacobian(
                self._jacobianMultiply(self._toJacobian(p), n, order, coeff, prime), prime
            )
        end

        def self.add(p, q, coeff, prime)
            # Fast way to add two points in elliptic curves
            #
            # :param p: First Point you want to add
            # :param q: Second Point you want to add
            # :param coeff: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
            # :param prime: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Point that represents the sum of First and Second Point
            return self._fromJacobian(
                self._jacobianAdd(self._toJacobian(p), self._toJacobian(q), coeff, prime), prime
            )
        end

        def self.multiplyAndAdd(p1, n1, p2, n2, order, coeff, prime)
            # Compute n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
            # Not constant-time - use only with public scalars (e.g. verification).
            #
            # :param p1: First point
            # :param n1: First scalar
            # :param p2: Second point
            # :param n2: Second scalar
            # :param order: Order of the elliptic curve
            # :param coeff: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
            # :param prime: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Point n1*p1 + n2*p2
            return self._fromJacobian(
                self._shamirMultiply(
                    self._toJacobian(p1), n1,
                    self._toJacobian(p2), n2,
                    order, coeff, prime,
                ), prime,
            )
        end

        def self.inv(x, n)
            # Modular inverse via extended Euclidean algorithm.
            # Roughly 2-3x faster than Fermat's little theorem for 256-bit operands.
            #
            # :param x: Divisor (must be coprime to n)
            # :param n: Mod for division
            # :return: Value representing the modular inverse
            if x % n == 0
                raise ArgumentError, "0 has no modular inverse"
            end

            a = x % n
            b = n
            x0 = 1
            x1 = 0
            while b != 0
                q = a / b
                a, b = b, a - q * b
                x0, x1 = x1, x0 - q * x1
            end
            return x0 % n
        end

        def self._toJacobian(p)
            # Convert point to Jacobian coordinates
            #
            # :param p: First Point you want to add
            # :return: Point in Jacobian coordinates
            return Point.new(p.x, p.y, 1)
        end

        def self._fromJacobian(p, prime)
            # Convert point back from Jacobian coordinates
            #
            # :param p: First Point you want to add
            # :param prime: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Point in default coordinates
            if p.y == 0
                return Point.new(0, 0, 0)
            end

            z = self.inv(p.z, prime)
            x = (p.x * z ** 2) % prime
            y = (p.y * z ** 3) % prime

            return Point.new(x, y, 0)
        end

        def self._jacobianDouble(p, coeff, prime)
            # Double a point in elliptic curves
            #
            # :param p: Point you want to double
            # :param coeff: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
            # :param prime: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Point that represents the sum of First and Second Point
            py = p.y
            if py == 0
                return Point.new(0, 0, 0)
            end

            px, pz = p.x, p.z
            ysq = (py * py) % prime
            s = (4 * px * ysq) % prime
            pz2 = (pz * pz) % prime
            if coeff == 0
                m = (3 * px * px) % prime
            elsif coeff == prime - 3
                m = (3 * (px - pz2) * (px + pz2)) % prime
            else
                m = (3 * px * px + coeff * pz2 * pz2) % prime
            end
            nx = (m * m - 2 * s) % prime
            ny = (m * (s - nx) - 8 * ysq * ysq) % prime
            nz = (2 * py * pz) % prime

            return Point.new(nx, ny, nz)
        end

        def self._jacobianAdd(p, q, coeff, prime)
            # Add two points in elliptic curves
            #
            # :param p: First Point you want to add
            # :param q: Second Point you want to add
            # :param coeff: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
            # :param prime: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Point that represents the sum of First and Second Point
            if p.y == 0
                return q
            end
            if q.y == 0
                return p
            end

            px, py, pz = p.x, p.y, p.z
            qx, qy, qz = q.x, q.y, q.z

            pz2 = (pz * pz) % prime
            u2 = (qx * pz2) % prime
            s2 = (qy * pz2 * pz) % prime

            if qz == 1
                # Mixed affine+Jacobian add: qz^2=qz^3=1 saves four multiplications.
                u1 = px
                s1 = py
            else
                qz2 = (qz * qz) % prime
                u1 = (px * qz2) % prime
                s1 = (py * qz2 * qz) % prime
            end

            if u1 == u2
                if s1 != s2
                    return Point.new(0, 0, 1)
                end
                return self._jacobianDouble(p, coeff, prime)
            end

            h = u2 - u1
            r = s2 - s1
            h2 = (h * h) % prime
            h3 = (h * h2) % prime
            u1h2 = (u1 * h2) % prime
            nx = (r * r - h3 - 2 * u1h2) % prime
            ny = (r * (u1h2 - nx) - s1 * h3) % prime
            nz = qz == 1 ? (h * pz) % prime : (h * pz * qz) % prime

            return Point.new(nx, ny, nz)
        end

        def self._jacobianMultiply(p, n, order, coeff, prime)
            # Multiply point and scalar in elliptic curves using Montgomery ladder
            # for constant-time execution.
            #
            # :param p: First Point to multiply
            # :param n: Scalar to multiply
            # :param order: Order of the elliptic curve
            # :param coeff: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
            # :param prime: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Point that represents the scalar multiplication
            if p.y == 0 or n == 0
                return Point.new(0, 0, 1)
            end

            if n < 0 or n >= order
                n = n % order
            end

            if n == 0
                return Point.new(0, 0, 1)
            end

            # Montgomery ladder: always performs one add and one double per bit
            r0 = Point.new(0, 0, 1)
            r1 = Point.new(p.x, p.y, p.z)

            (n.bit_length - 1).downto(0) do |i|
                if (n >> i) & 1 == 0
                    r1 = self._jacobianAdd(r0, r1, coeff, prime)
                    r0 = self._jacobianDouble(r0, coeff, prime)
                else
                    r0 = self._jacobianAdd(r0, r1, coeff, prime)
                    r1 = self._jacobianDouble(r1, coeff, prime)
                end
            end

            return r0
        end

        def self._shamirMultiply(jp1, n1, jp2, n2, order, coeff, prime)
            # Compute n1*p1 + n2*p2 using Shamir's trick with Joint Sparse Form
            # (Solinas 2001). JSF picks signed digits in {-1, 0, 1} so at most ~l/2
            # digit pairs are non-zero, versus ~3l/4 for the raw binary form. Not
            # constant-time - use only with public scalars (e.g. verification).
            #
            # :param jp1: First point in Jacobian coordinates
            # :param n1: First scalar
            # :param jp2: Second point in Jacobian coordinates
            # :param n2: Second scalar
            # :param order: Order of the elliptic curve
            # :param coeff: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
            # :param prime: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Point n1*p1 + n2*p2 in Jacobian coordinates
            if n1 < 0 or n1 >= order
                n1 = n1 % order
            end
            if n2 < 0 or n2 >= order
                n2 = n2 % order
            end

            if n1 == 0 and n2 == 0
                return Point.new(0, 0, 1)
            end

            neg = lambda { |pt| Point.new(pt.x, pt.y == 0 ? 0 : prime - pt.y, pt.z) }

            jp1p2 = self._jacobianAdd(jp1, jp2, coeff, prime)
            jp1mp2 = self._jacobianAdd(jp1, neg.call(jp2), coeff, prime)
            addTable = {
                [1, 0]   => jp1,
                [-1, 0]  => neg.call(jp1),
                [0, 1]   => jp2,
                [0, -1]  => neg.call(jp2),
                [1, 1]   => jp1p2,
                [-1, -1] => neg.call(jp1p2),
                [1, -1]  => jp1mp2,
                [-1, 1]  => neg.call(jp1mp2),
            }

            digits = self._jsfDigits(n1, n2)
            r = Point.new(0, 0, 1)
            digits.each do |u0, u1|
                r = self._jacobianDouble(r, coeff, prime)
                if u0 != 0 or u1 != 0
                    r = self._jacobianAdd(r, addTable[[u0, u1]], coeff, prime)
                end
            end

            return r
        end

        def self._jsfDigits(k0, k1)
            # Joint Sparse Form of (k0, k1): list of signed-digit pairs (u0, u1) in
            # {-1, 0, 1}, ordered MSB-first. At most one of any two consecutive pairs
            # is non-zero, giving density ~1/2 instead of ~3/4 from raw binary.
            digits = []
            d0 = 0
            d1 = 0
            while k0 + d0 != 0 or k1 + d1 != 0
                a0 = k0 + d0
                a1 = k1 + d1
                if (a0 & 1) != 0
                    u0 = (a0 & 3) == 1 ? 1 : -1
                    if [3, 5].include?(a0 & 7) and (a1 & 3) == 2
                        u0 = -u0
                    end
                else
                    u0 = 0
                end
                if (a1 & 1) != 0
                    u1 = (a1 & 3) == 1 ? 1 : -1
                    if [3, 5].include?(a1 & 7) and (a0 & 3) == 2
                        u1 = -u1
                    end
                else
                    u1 = 0
                end
                digits << [u0, u1]
                if 2 * d0 == 1 + u0
                    d0 = 1 - d0
                end
                if 2 * d1 == 1 + u1
                    d1 = 1 - d1
                end
                k0 >>= 1
                k1 >>= 1
            end
            digits.reverse
        end
    end
end
