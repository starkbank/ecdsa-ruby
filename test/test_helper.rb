require 'minitest/autorun'
require 'minitest/spec'

require './lib/starkbank-ecdsa'

def read_file(path, encoding="ASCII")
  File.read(path, :encoding => encoding.upcase)
end