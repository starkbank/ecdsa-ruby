module EllipticCurve
    class Point
        def initialize(x=0, y=0, z=0)
            @x = x
            @y = y
            @z = z
        end

        attr_accessor :x, :y, :z

        def to_s
            return "(#{@x}, #{@y}, #{@z})"
        end

        def isAtInfinity()
            return @y == 0
        end
    end
end
