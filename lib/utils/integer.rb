require('securerandom')

module EllipticCurve
    module Utils
        class RandomInteger
            # Return integer x in the range: min <= x <= max

            # Parameters (required):
            # :param min: minimum value of the integer
            # :param max: maximum value of the integer 
            # :return: A random number between min and max
            def self.between(min, max)
                if (max - min) < 0 then
                    raise Exception.new("max must be greater than min")
                end
                if (max - min) > 0 then
                    return SecureRandom.random_number((max + 1) - min) + min
                end
                return min
            end
        end
    end
end
