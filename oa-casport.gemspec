# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "oa-casport/version"

Gem::Specification.new do |s|
  s.name        = "oa-casport"
  s.version     = OmniAuth::Casport::VERSION
  s.authors     = ["Steven Haddox"]
  s.email       = ["steven@haddox.us"]
  s.homepage    = ""
  s.summary     = %q{OmniAuth gem for internal casport server}
  s.description = %q{ Simple gem to enable rack powered Ruby apps to authenticate internally via CASPORT with ease}
  s.rubyforge_project = "oa-casport"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]
end