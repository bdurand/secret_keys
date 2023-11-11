require_relative "../lib/secret_keys"

require "tempfile"

RSpec.configure do |config|
  config.warnings = true
  config.order = :random
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
