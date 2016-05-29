# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'live_identity/version'

Gem::Specification.new do |spec|
  spec.name          = 'LiveIdentity'
  spec.version       = LiveIdentity::VERSION
  spec.authors       = ['Dāvis']
  spec.email         = ['davispuh@gmail.com']
  spec.summary       = 'Wrapper around IDCRL (Identity Client Runtime Library).'
  spec.description   = 'Library utilizing IDCRL for Microsoft Windows Live ID authentication.'
  spec.homepage      = 'https://github.com/davispuh/LiveIdentity'
  spec.license       = 'UNLICENSE'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_runtime_dependency 'WinCommon', '>= 0.1.0'
  spec.add_runtime_dependency 'ffi'
  spec.add_runtime_dependency 'nokogiri'

  spec.add_development_dependency 'bundler', '~> 1.12'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec'
  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency 'yard'
end

