module EllipticCurve
    module Utils
        class Pem
            def self.getContent(pem, template)
                pattern = template.sub "{content}", ("(.*)")
                return pem.split("\n").join("").match(pattern.split("\n").join("")).captures[0]
            end

            def self.create(content, template)
                lines = []
                (0..content.length).step(64) do |start|
                    lines.append(content[start..start+63])
                end
                return template.sub "{content}", lines.join("\n")
            end
        end
    end
end
