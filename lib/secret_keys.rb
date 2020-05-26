# frozen_string_literal: true

require "openssl"
require "json"
require "yaml"
require "securerandom"
require "delegate"
require "set"
require "pathname"
require "base64"

# Load a JSON file with encrypted values. This value can be used as a hash.
class SecretKeys < DelegateClass(Hash)
  class EncryptionKeyError < ArgumentError; end

  # Parse a JSON stream or file with encrypted values. Any values in the ".encrypted" key
  # in the JSON document will be decrypted with the provided encryption key. If values
  # were put into the ".encrypted" key manually and are not yet encrypted, they will be used
  # as is without any decryption.
  #
  # @param [String, #read, Hash] path_or_stream path to a json/yaml file to load, an IO object, or a Hash (mostly for testing purposes)
  # @param [String] encryption_key secret to use for encryption/decryption
  #
  # @note If no encryption key is passed, this will defautl to env var SECRET_KEYS_ENCRYPTION_KEY
  # or (if that is empty) the value read from the file path in SECRET_KEYS_ENCRYPTION_KEY_FILE.
  def initialize(path_or_stream, encryption_key = nil)
    @encryption_key = nil
    @salt = nil

    encryption_key = read_encryption_key(encryption_key)
    update_secret(key: encryption_key)
    path_or_stream = Pathname.new(path_or_stream) if path_or_stream.is_a?(String)
    load_secrets!(path_or_stream)
    # if no salt exists, create one.
    update_secret(salt: SecureRandom.hex(8)) if @salt.nil?
    super(@values)
  end

  # Convert the value into an actual Hash object.
  #
  # @return [Hash]
  def to_h
    @values
  end
  alias to_hash to_h

  # Mark the key as being encrypted when the JSON is saved.
  #
  # @param [String] key key to mark as needing encryption
  # @return [void]
  def encrypt!(key)
    @secret_keys << key
    nil
  end

  # Mark the key as no longer being decrypted when the JSON is saved.
  #
  # @param [String] key key to mark as not needing encryption
  # @return [void]
  def decrypt!(key)
    @secret_keys.delete(key)
    nil
  end

  # Return true if the key is encrypted.
  #
  # @param [String] key key to check
  # @return [Boolean]
  def encrypted?(key)
    @secret_keys.include?(key)
  end

  # Save the JSON to a file at the specified path. Encrypted values in the file
  # will not be updated if the values have not changed (since each call uses a
  # different initialization vector).
  #
  # @param [String] path Filepath to save to. Supports yaml and json format as the extension
  # @param [Boolean] update: check to see if values have been changed before overwriting
  # @return [void]
  def save(path, update: true)
    # create a copy of the encrypted hash for working on
    encrypted = encrypted_hash

    if File.exist?(path) && update
      original_data = File.read(path)
      original_hash = parse_data(original_data)
      original_encrypted = original_hash[ENCRYPTED] if original_hash
      # only check for unchanged keys if the original had encryption with the same key
      if original_encrypted && encryption_key_matches?(original_encrypted[ENCRYPTION_KEY])
        restore_unchanged_keys!(encrypted[ENCRYPTED], original_encrypted)
      end
    end

    output = (yaml_file?(path) ? YAML.dump(encrypted) : "#{JSON.pretty_generate(encrypted)}#{$/}")
    File.open(path, "w") do |file|
      file.write(output)
    end
    nil
  end

  # Output the keys as a hash that matches the structure that can be loaded by the initalizer.
  # Note that all encrypted values will be re-salted when they are encrypted.
  #
  # @return [Hash] An encrypted hash that can be saved/parsed by a new instance of {SecretKeys}
  def encrypted_hash
    raise EncryptionKeyError.new("Encryption key not specified") if @encryption_key.nil? || @encryption_key.empty?

    hash = {}
    encrypted = {}
    @values.each do |key, value|
      if @secret_keys.include?(key)
        encrypted[key] = value
      else
        hash[key] = value
      end
    end
    encrypted = {
      SALT => @salt,
      ENCRYPTION_KEY => key_dummy_value
    }.merge(encrypt_values(encrypted))

    hash[ENCRYPTED] = encrypted
    hash
  end

  # Change the encryption key in the document. When saving later, this key will be used.
  #
  # @param [String] new_encryption_key encryption key to use for future {#save} calls
  # @return [void]
  def encryption_key=(new_encryption_key)
    update_secret(key: new_encryption_key)
  end

  private

  ENCRYPTED = ".encrypted"
  ENCRYPTION_KEY = ".key"
  SALT = ".salt"

  # Used as a known dummy value for verifying we have the correct key
  # DO NOT CHANGE!!!
  KNOWN_DUMMY_VALUE = "SECRET_KEY"

  # Load the JSON data in a file path or stream into a hash, decrypting all the encrypted values.
  #
  # @return [void]
  def load_secrets!(path_or_stream)
    @secret_keys = Set.new
    @values = {}

    hash = nil
    if path_or_stream.is_a?(Hash)
      # HACK: Perform a marshal dump/load operation to get a deep copy of the hash.
      #       Otherwise, we can end up using destructive `#delete` operations and mess
      #       up deeply nested values for external code (esp. when loading key: .encrypted)
      hash = Marshal.load(Marshal.dump(path_or_stream))
    elsif path_or_stream
      data = path_or_stream.read
      hash = parse_data(data)
    end
    return if hash.nil? || hash.empty?

    encrypted_values = hash.delete(ENCRYPTED)
    if encrypted_values
      file_key = encrypted_values.delete(ENCRYPTION_KEY)
      update_secret(salt: encrypted_values.delete(SALT))

      # Check that we are using the right key
      if file_key && !encryption_key_matches?(file_key)
        raise EncryptionKeyError.new("Incorrect encryption key")
      end
      @secret_keys = encrypted_values.keys
      hash.merge!(decrypt_values(encrypted_values))
    end

    @values = hash
  end

  # Attempt to parse the file first using JSON and fallback to YAML
  # @param [String] data file data to parse
  # @return [Hash] data parsed to a hash
  def parse_data(data)
    JSON.parse(data)
  rescue JSON::JSONError
    YAML.safe_load(data)
  end

  # Recursively encrypt all values.
  def encrypt_values(values)
    if values.is_a?(Hash)
      encrypted_hash = {}
      values.keys.each do |key|
        encrypted_hash[key.to_s] = encrypt_values(values[key])
      end
      encrypted_hash
    elsif values.is_a?(Enumerable)
      values.collect { |value| encrypt_values(value) }
    else
      encrypt_value(values)
    end
  end

  # Recursively decrypt all values.
  def decrypt_values(values)
    if values.is_a?(Hash)
      decrypted_hash = {}
      values.each do |key, value|
        decrypted_hash[key.to_s] = decrypt_values(value)
      end
      decrypted_hash
    elsif values.is_a?(Enumerable)
      values.collect { |value| decrypt_values(value) }
    else
      decrypt_value(values)
    end
  end

  # Since the encrypted values include a salt, make sure we don't overwrite values in the stored
  # documents when the decrypted values haven't changed since this would mess up any file history
  # in a source code repository.
  def restore_unchanged_keys!(new_hash, old_hash)
    if new_hash.is_a?(Hash) && old_hash.is_a?(Hash)
      new_hash.keys.each do |key|
        new_value = new_hash[key]
        old_value = old_hash[key]
        next if new_value == old_value

        if new_value.is_a?(Enumerable) && old_value.is_a?(Enumerable)
          restore_unchanged_keys!(new_value, old_value)
        elsif equal_encrypted_values?(new_value, old_value)
          new_hash[key] = old_value
        end
      end
    elsif new_hash.is_a?(Array) && old_hash.is_a?(Array)
      new_hash.size.times do |i|
        new_val = new_hash[i]
        old_val = old_hash[i]
        if new_val != old_val
          if new_val.is_a?(Enumerable) && old_val.is_a?(Enumerable)
            restore_unchanged_keys!(new_val, old_val)
          elsif equal_encrypted_values?(new_val, old_val)
            new_hash[i] = old_val
          end
        end
      end
    end
  end

  # Helper method to encrypt a value.
  def encrypt_value(value)
    @encryptor.encrypt(value)
  end

  # Helper method to decrypt a value.
  def decrypt_value(encrypted_value)
    @encryptor.decrypt(encrypted_value)
  end

  # Helper method to test if two values are both encrypted, but result in the same decrypted value.
  def equal_encrypted_values?(value_1, value_2)
    return true if value_1 == value_2

    decrypt_val_1 = decrypt_value(value_1)
    decrypt_val_2 = decrypt_value(value_2)
    if decrypt_val_1 == decrypt_val_2
      if value_1 == decrypt_val_1 || value_2 == decrypt_val_2
        false
      else
        true
      end
    else
      false
    end
  end

  # This is a
  def key_dummy_value
    encrypt_value(KNOWN_DUMMY_VALUE)
  end

  # Helper to check if our encryption key is correct
  def encryption_key_matches?(encrypted_key)
    decrypt_value(encrypted_key) == KNOWN_DUMMY_VALUE
  rescue OpenSSL::Cipher::CipherError
    # If the key fails to decrypt, then it cannot be correct
    false
  end

  def yaml_file?(path)
    ext = path.split(".").last.to_s.downcase
    ext == "yaml" || ext == "yml"
  end

  # Update the secret key by updating the salt
  #
  # @param key: new encryption key
  # @param salt: salt to use for secret
  # @return [void]
  def update_secret(key: nil, salt: nil)
    @encryption_key = key unless key.nil? || key.empty?
    @salt = salt unless salt.nil? || salt.empty?

    # Only update the secret if encryption key and salt are present
    if !@encryption_key.nil? && !@salt.nil?
      @encryptor = Encryptor.new(@encryption_key, @salt)
    end
    # Don't accidentally return the secret, dammit
    nil
  end

  # Logic to read an encryption key from environment variables if it is not explicitly supplied.
  # If it isn't specified, the value will be read from the SECRET_KEYS_ENCRYPTION_KEY environment
  # variable. Otherwise, it will be tried to read from the file specified by the
  # SECRET_KEYS_ENCRYPTION_KEY_FILE environment variable.
  # @return [String, nil] the encryption key
  def read_encryption_key(encryption_key)
    return encryption_key if encryption_key && !encryption_key.empty?
    encryption_key = ENV["SECRET_KEYS_ENCRYPTION_KEY"]
    return encryption_key if encryption_key && !encryption_key.empty?
    encryption_key_file = ENV["SECRET_KEYS_ENCRYPTION_KEY_FILE"]

    encryption_key = nil
    if encryption_key_file && !encryption_key_file.empty? && File.exist?(encryption_key_file)
      encryption_key = File.read(encryption_key_file).chomp
    end

    encryption_key
  end
end

require_relative "secret_keys/encryptor"
