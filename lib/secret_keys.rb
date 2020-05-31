# frozen_string_literal: true

require "openssl"
require "json"
require "yaml"
require "delegate"
require "set"
require "pathname"

# Load a JSON file with encrypted values. This value can be used as a hash.
class SecretKeys < DelegateClass(Hash)
  class EncryptionKeyError < ArgumentError; end

  # Parse a JSON or YAML stream or file with encrypted values. Any values in the ".encrypted" key
  # in the document will be decrypted with the provided encryption key. If values
  # were put into the ".encrypted" key manually and are not yet encrypted, they will be used
  # as is without any decryption.
  #
  # @param [String, #read, Hash] path_or_stream path to a JSON/YAML file to load, an IO object, or a Hash (mostly for testing purposes)
  # @param [String] encryption_key secret to use for encryption/decryption
  #
  # @note If no encryption key is passed, this will defautl to env var SECRET_KEYS_ENCRYPTION_KEY
  # or (if that is empty) the value read from the file path in SECRET_KEYS_ENCRYPTION_KEY_FILE.
  def initialize(path_or_stream, encryption_key = nil)
    @encryption_key = nil
    @salt = nil
    @format = :json

    encryption_key = read_encryption_key(encryption_key)
    update_secret(key: encryption_key)
    path_or_stream = Pathname.new(path_or_stream) if path_or_stream.is_a?(String)
    load_secrets!(path_or_stream)

    super(@values)
  end

  # Convert into an actual Hash object.
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

  # Save the encrypted hash to a file at the specified path. Encrypted values in an existing file
  # will not be updated if the values have not changed (since each call uses a
  # different initialization vector). This can be helpful if you have your secrets in source
  # control so that only changed keys will actually be changed in the file when it is updated.
  #
  # @param [String, Pathname] path path of the file to save. If the file exists, only changed values will be updated.
  # @param [String, Symbol] format: output format (YAML or JSON) to use. This will default based on the extension on the file path or the format originally used
  # @return [void]
  def save(path, format: nil)
    # create a copy of the encrypted hash for working on
    encrypted = encrypted_hash

    if format.nil?
      if yaml_file?(path)
        format = :yaml
      elsif json_file?(path)
        format = :json
      end
    end
    format ||= @format
    format = format.to_s.downcase

    output = (format == "yaml" ? YAML.dump(encrypted) : JSON.pretty_generate(encrypted))
    output << $/ unless output.end_with?($/) # ensure file ends with system dependent new line
    File.open(path, "w") do |file|
      file.write(output)
    end
    nil
  end

  # Output the keys as a hash that matches the structure that can be loaded by the initalizer.
  # Values that have not changed will not be re-salted so the encrypted values will remain the same.
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

    unless encryption_key_matches?(@original_encrypted[ENCRYPTION_KEY])
      @original_encrypted = {}
    end
    encrypted.merge!(encrypt_values(encrypted, @original_encrypted))
    encrypted[SALT] = @salt
    encrypted[ENCRYPTION_KEY] = (@original_encrypted[ENCRYPTION_KEY] || encrypted_known_value)

    hash[ENCRYPTED] = encrypted
    hash
  end

  # Change the encryption key in the document. When saving later, this key will be used.
  #
  # @param [String] new_encryption_key encryption key to use for future {#save} calls
  # @return [void]
  def encryption_key=(new_encryption_key)
    @original_encrypted = {}
    update_secret(key: new_encryption_key)
  end

  # Return the data format (:json or :yaml) for the original data. Defaults to :json.
  #
  # @return [String]
  def input_format
    @format
  end

  private

  ENCRYPTED = ".encrypted"
  ENCRYPTION_KEY = ".key"
  SALT = ".salt"

  # Used as a known value for verifying we have the correct key
  # DO NOT CHANGE!!!
  KNOWN_VALUE = "SECRET_KEY"

  # Load the JSON data in a file path or stream into a hash, decrypting all the encrypted values.
  #
  # @return [void]
  def load_secrets!(path_or_stream)
    @secret_keys = Set.new
    @values = {}
    @original_encrypted = {}

    hash = {}
    if path_or_stream.is_a?(Hash)
      # HACK: Perform a marshal dump/load operation to get a deep copy of the hash.
      #       Otherwise, we can end up using destructive `#delete` operations and mess
      #       up deeply nested values for external code (esp. when loading key: .encrypted)
      hash = Marshal.load(Marshal.dump(path_or_stream))
    elsif path_or_stream
      data = path_or_stream.read
      hash = parse_data(data)
    end

    encrypted_values = hash.delete(ENCRYPTED)
    if encrypted_values
      raise EncryptionKeyError.new("Encryption key not specified") if @encryption_key.nil? || @encryption_key.empty?

      @original_encrypted = Marshal.load(Marshal.dump(encrypted_values))
      file_key = encrypted_values.delete(ENCRYPTION_KEY)
      salt = (encrypted_values.delete(SALT) || Encryptor.random_salt)
      update_secret(salt: salt)

      # Check that we are using the right key
      if file_key && !encryption_key_matches?(file_key)
        raise EncryptionKeyError.new("Incorrect encryption key")
      end
      @secret_keys = encrypted_values.keys
      hash.merge!(decrypt_values(encrypted_values))
    elsif @salt.nil?
      # if no salt exists, create one.
      update_secret(salt: Encryptor.random_salt)
    end

    @values = hash
  end

  # Attempt to parse the file first using JSON and fallback to YAML
  # @param [String] data file data to parse
  # @return [Hash] data parsed to a hash
  def parse_data(data)
    @format = :json
    return {} if data.nil? || data.empty?
    JSON.parse(data)
  rescue JSON::JSONError
    @format = :yaml
    YAML.safe_load(data)
  end

  # Recursively encrypt all values.
  def encrypt_values(values, original)
    if values.is_a?(Hash)
      encrypted_hash = {}
      values.each_key do |key|
        key = key.to_s
        original_value = original[key] if original.is_a?(Hash)
        encrypted_hash[key] = encrypt_values(values[key], original_value)
      end
      encrypted_hash
    elsif values.is_a?(Enumerable)
      if original.is_a?(Enumerable)
        values.zip(original).collect { |value, original_value| encrypt_values(value, original_value) }
      else
        values.collect { |value| encrypt_values(value, nil) }
      end
    else
      decrypted_original = decrypt_value(original)
      if decrypted_original == values && decrypted_original != original
        original
      else
        encrypt_value(values)
      end
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

  # This is an encrypted known value that can be used determine if the secret has changed.
  def encrypted_known_value
    encrypt_value(KNOWN_VALUE)
  end

  # Helper to check if our encryption key is correct
  def encryption_key_matches?(encrypted_key)
    decrypt_value(encrypted_key) == KNOWN_VALUE
  rescue OpenSSL::Cipher::CipherError
    # If the key fails to decrypt, then it cannot be correct
    false
  end

  def yaml_file?(path)
    ext = path.split(".").last.to_s.downcase
    ext == "yaml" || ext == "yml"
  end

  def json_file?(path)
    ext = path.split(".").last.to_s.downcase
    ext == "json"
  end

  # Update the secret key by updating the salt
  #
  # @param key new encryption key
  # @param salt salt to use for secret
  # @return [void]
  def update_secret(key: nil, salt: nil)
    @encryption_key = key unless key.nil? || key.empty?
    @salt = salt unless salt.nil? || salt.empty?

    # Only update the secret if encryption key and salt are present
    if !@encryption_key.nil? && !@salt.nil?
      @encryptor = Encryptor.from_password(@encryption_key, @salt)
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

    encryption_key = nil
    encryption_key_file = ENV["SECRET_KEYS_ENCRYPTION_KEY_FILE"]
    if encryption_key_file && !encryption_key_file.empty? && File.exist?(encryption_key_file)
      encryption_key = File.read(encryption_key_file).chomp
    end

    encryption_key
  end
end

require_relative "secret_keys/encryptor"
