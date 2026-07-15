# frozen_string_literal: true

ENV["BUNDLE_GEMFILE"] ||= File.expand_path("../Gemfile", __dir__)

require "bundler/setup" if File.exist?(ENV["BUNDLE_GEMFILE"])

require_relative "../lib/secret_keys"

require "tempfile"

RSpec.configure do |config|
  config.warnings = true
  config.disable_monkey_patching!
  config.default_formatter = "doc" if config.files_to_run.one?
  config.order = :random
  Kernel.srand config.seed
end

# Helper method to temporarily set environment variables.
def with_environment(env)
  save_vals = env.keys.collect { |k| [k, ENV[k.to_s]] }
  begin
    env.each { |k, v| ENV[k.to_s] = v }
    yield
  ensure
    save_vals.each { |k, v| ENV[k.to_s] = v }
  end
end
