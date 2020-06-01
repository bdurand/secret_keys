# frozen_string_literal: true

class SecretKeys
  VERSION = File.read(File.join(__dir__, "..", "..", "VERSION")).chomp.freeze
  CRYPTO_VERSION = 1
end
