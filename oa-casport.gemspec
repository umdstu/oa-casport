# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "oa-casport/version"

Gem::Specification.new do |s|
  s.name        = "oa-casport"
  s.version     = OmniAuth::Casport::VERSION
  s.authors     = ["Chase Pollock"]
  s.email       = ["umdstu@gmail.com"]
  s.homepage    = "https://github.com/umdstu/oa-casport"
  s.summary     = %q{OmniAuth gem for internal casport server}
  s.description = %q{ Simple gem to enable rack powered Ruby apps to authenticate internally via casport with ease}
  s.rubyforge_project = "oa-casport"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_dependency 'omniauth', '~> 1.1.0'
  s.add_dependency 'httparty'
  s.add_dependency 'redis'

  s.add_development_dependency 'rack'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'fakeweb'
end
