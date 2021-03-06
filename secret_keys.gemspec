Gem::Specification.new do |spec|
  spec.name = "secret_keys"
  spec.version = File.read(File.join(__dir__, "VERSION")).strip
  spec.authors = ["Brian Durand", "Winston Durand"]
  spec.email = ["bbdurand@gmail.com", "me@winstondurand.com"]

  spec.summary = "Simple mechanism for loading JSON file with encrypted values."
  spec.homepage = "https://github.com/bdurand/secret_keys"
  spec.license = "MIT"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/bdurand/secret_keys/tree/v#{spec.version}"
  spec.metadata["documentation_uri"] = "https://www.rubydoc.info/gems/secret_keys"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  ignore_files = %w[
    .
    Appraisals
    Gemfile
    Rakefile
    gemfiles/
    spec/
  ]
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject { |f| ignore_files.any? { |path| f.start_with?(path) } }
  end

  spec.require_paths = ["lib"]
  spec.bindir = "bin"
  spec.executables = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }

  spec.required_ruby_version = ">= 2.4"

  spec.add_development_dependency "bundler", "~>2.0"
end
