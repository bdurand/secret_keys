require_relative "../lib/secret_keys"

require "tempfile"
require "climate_control"

RSpec.configure do |config|
  config.warnings = true
  config.order = :random
end
