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
            # Modular inverse using Fermat's little theorem: x^(n-2) mod n.
            # Requires n to be prime (true for all ECDSA curve parameters).
            # Uses Ruby's built-in pow() which has more uniform execution time
            # than the extended Euclidean algorithm.
            #
            # :param x: Divisor
            # :param n: Mod for division (must be prime)
            # :return: Value representing the division
            if x == 0
                return 0
            end

            return x.pow(n - 2, n)
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
            m = (3 * px * px + coeff * pz2 * pz2) % prime
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

            qz2 = (qz * qz) % prime
            pz2 = (pz * pz) % prime
            u1 = (px * qz2) % prime
            u2 = (qx * pz2) % prime
            s1 = (py * qz2 * qz) % prime
            s2 = (qy * pz2 * pz) % prime

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
            nz = (h * pz * qz) % prime

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
            # Compute n1*p1 + n2*p2 using Shamir's trick (simultaneous double-and-add).
            # Not constant-time - use only with public scalars (e.g. verification).
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

            jp1p2 = self._jacobianAdd(jp1, jp2, coeff, prime)

            l = [n1.bit_length, n2.bit_length].max
            r = Point.new(0, 0, 1)

            (l - 1).downto(0) do |i|
                r = self._jacobianDouble(r, coeff, prime)
                b1 = (n1 >> i) & 1
                b2 = (n2 >> i) & 1
                if b1 != 0
                    r = self._jacobianAdd(r, b2 != 0 ? jp1p2 : jp1, coeff, prime)
                elsif b2 != 0
                    r = self._jacobianAdd(r, jp2, coeff, prime)
                end
            end

            return r
        end
    end
end
