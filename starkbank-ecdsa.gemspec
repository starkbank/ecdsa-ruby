Gem::Specification.new do |s|
  s.name = %q{starkbank-ecdsa}
  s.version = "0.0.5"
  s.date = %q{2019-11-21}
  s.summary = %q{fast openSSL-compatible implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA)}
  s.authors = "starkbank"
  s.homepage = "https://github.com/starkbank/ecdsa-ruby"
  s.files = Dir['lib/**/*.rb']
  s.license = "MIT"
  s.required_ruby_version = '>= 2.4'
  s.add_development_dependency "rake", "~> 13.0"
  s.add_development_dependency "minitest", "~> 5.14.1"
end
