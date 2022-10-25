module EllipticCurve
    class Math
        def self.modularSquareRoot(value, prime)
            # :param value: Value to calculate the square root
            # :param prime: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Square root of the value
            return value.pow((prime + 1).div(4), prime)
        end

        def self.multiply(p, n, order, coeff, prime) 
            # Fast way to multiply point and scalar in elliptic curves

            # :param p: First Point to mutiply
            # :param n: Scalar to mutiply
            # :param N: Order of the elliptic curve
            # :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
            # :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Point that represents the sum of First and Second Point
            return self._fromJacobian(
                self._jacobianMultiply(self._toJacobian(p), n, order, coeff, prime), prime
            )
        end

        def self.add(p, q, coeff, prime)
            # Fast way to add two points in elliptic curves

            # :param p: First Point you want to add
            # :param q: Second Point you want to add
            # :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Point that represents the sum of First and Second Point
            return self._fromJacobian(
                self._jacobianAdd(self._toJacobian(p), self._toJacobian(q), coeff, prime), prime
            )
        end

        def self.inv(x, n)
            # Extended Euclidean Algorithm. It's the 'division' in elliptic curves

            # :param x: Divisor
            # :param n: Mod for division
            # :return: Value representing the division
            if x == 0 then return 0 end
            
            lm = 1
            hm = 0
            low = x % n
            high = n

            while low > 1
                r = high.div(low)
                nm = hm - lm * r
                nw = high - low * r
                high = low
                hm = lm
                low = nw
                lm = nm
            end
            return lm % n 
        end

        def self._toJacobian(p)
            # Convert point to Jacobian coordinates

            # :param p: First Point you want to add
            # :return: Point in Jacobian coordinates
            return Point.new(p.x, p.y, 1)
        end

        def self._fromJacobian(p, prime)
            # Convert point back from Jacobian coordinates

            # :param p: First Point you want to add
            # :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Point in default coordinates
            z = self.inv(p.z, prime)
            x = (p.x * z ** 2) % prime
            y = (p.y * z ** 3) % prime

            return Point.new(x, y, 0)
        end

        def self._jacobianDouble(p, coeff, prime)
            # Double a point in elliptic curves

            # :param p: Point you want to double
            # :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
            # :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Point that represents the sum of First and Second Point
            if p.y == 0 then return Point.new(0, 0, 0) end

            ysq = (p.y ** 2) % prime
            s = (4 * p.x * ysq) % prime
            m = (3 * p.x ** 2 + coeff * p.z ** 4) % prime
            nx = (m ** 2 - 2 * s) % prime
            ny = (m * (s - nx) - 8 * ysq ** 2) % prime
            nz = (2 * p.y * p.z) % prime

            return Point.new(nx, ny, nz)
        end

        def self._jacobianAdd(p, q, coeff, prime)
            # Add two points in elliptic curves

            # :param p: First Point you want to add
            # :param q: Second Point you want to add
            # :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
            # :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Point that represents the sum of First and Second Point
            if p.y == 0 then return q end
            if q.y == 0 then return p end

            u1 = (p.x * q.z ** 2) % prime
            u2 = (q.x * p.z ** 2) % prime
            s1 = (p.y * q.z ** 3) % prime
            s2 = (q.y * p.z ** 3) % prime

            if u1 == u2
                if s1 != s2 then return Point.new(0, 0, 1) end
                return self._jacobianDouble(p, coeff, prime)
            end

            h = u2 - u1
            r = s2 - s1
            h2 = (h * h) % prime
            h3 = (h * h2) % prime
            u1h2 = (u1 * h2) % prime
            nx = (r ** 2 - h3 - 2 * u1h2) % prime
            ny = (r * (u1h2 - nx) - s1 * h3) % prime
            nz = (h * p.z * q.z) % prime

            return Point.new(nx, ny, nz)
        end

        def self._jacobianMultiply(p, n, order, coeff, prime)
            # Multiply point and scalar in elliptic curves

            # :param p: First Point to mutiply
            # :param n: Scalar to mutiply
            # :param N: Order of the elliptic curve
            # :param P: Prime number in the module of the equation Y^2 = X^3 + A*X + B (mod p)
            # :param A: Coefficient of the first-order term of the equation Y^2 = X^3 + A*X + B (mod p)
            # :return: Point that represents the sum of First and Second Point
            if p.y == 0 or n == 0
                return Point.new(0, 0, 1)
            end

            if n == 1
                return p
            end

            if n < 0 or n >= order
                return self._jacobianMultiply(p, n % order, order, coeff, prime)
            end

            if (n % 2) == 0
                return self._jacobianDouble(
                    self._jacobianMultiply(p, n.div(2), order, coeff, prime), coeff, prime
                )
            end

            return self._jacobianAdd(
                self._jacobianDouble(self._jacobianMultiply(p, n.div(2), order, coeff, prime), coeff, prime), p, coeff, prime
            )
        end
    end
end
