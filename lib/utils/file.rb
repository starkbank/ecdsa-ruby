class File
    def self.read(path, encoding="ASCII")
        file = File.open(path, :encoding => encoding.upcase)
        content = file.read
        file.close
        return content
    end
end