Gem::Specification.new do |spec|
  spec.name = 'secret_keys'
  spec.version = File.read(File.expand_path("../VERSION", __FILE__)).strip
  spec.authors = ['Brian Durand', 'Winston Durand']
  spec.email = ['bbdurand@gmail.com', 'me@winstondurand.com']

  spec.summary = "Simple mechanism for loading JSON file with encrypted values."
  spec.homepage = "https://github.com/bdurand/secret_keys"
  spec.license = "MIT"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  ignore_files = %w(
    .gitignore
    .travis.yml
    Appraisals
    Gemfile
    Gemfile.lock
    Rakefile
    gemfiles/
    spec/
  )
  spec.files = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject{ |f| ignore_files.any?{ |path| f.start_with?(path) } }
  end

  spec.require_paths = ['lib']
  spec.bindir        = "bin"
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }

  spec.add_development_dependency("rspec", ["~> 3.0"])
  spec.add_development_dependency "rake"
  spec.add_development_dependency "yard"
end
