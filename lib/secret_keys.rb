# frozen_string_literal: true

require 'openssl'
require 'json'
require 'yaml'
require 'securerandom'
require 'delegate'
require 'set'
require 'pathname'
require 'base64'

# Load a JSON file with encrypted values. This value can be used as a hash.
class SecretKeys < DelegateClass(Hash)

  class EncryptionKeyError < ArgumentError; end

  class << self

    # Encrypt a string with the encryption key. Encrypted values are also salted so
    # calling this function multiple times will result in different values. Only strings
    # can be encrypted. Any other object type will be returned the value passed in.
    #
    # @param [String] str string to encrypt (assumes UTF-8)
    # @param [String] secret_key 32 byte ASCII-8BIT encryption key
    # @return [String] Base64 encoded encrypted string with all aes parameters
    def encrypt(str, secret_key)
      return str unless str.is_a?(String) && secret_key
      return "" if str == ""

      cipher = OpenSSL::Cipher.new(CIPHER).encrypt

      # Technically, this is a "bad" way to do things since we could theoretically
      # get a repeat nonce, compromising the algorithm. That said, it should be safe
      # from repeats as long as we don't use this key for more than 2^32 encryptions
      # so... rotate your keys/salt ever 4 billion encryption calls
      nonce = cipher.random_iv
      cipher.key = secret_key
      cipher.auth_data = ""

      # Make sure the string is encoded as UTF-8. JSON/YAML only support string types
      # anyways, so if you passed in binary data, it was gonna fail anyways. This ensures
      # that we can easily decode the string later. If you have UTF-16 or something, deal with it.
      utf8_str = str.encode('UTF-8')
      encrypted_data = cipher.update(utf8_str) + cipher.final
      auth_tag = cipher.auth_tag

      params = CipherParams.new(nonce, auth_tag, encrypted_data)

      encode_aes(params).prepend(ENCRYPTED_PREFIX)
    end

    # Decrypt a string with the encryption key. If the value is not a string or it was
    # not encrypted with the encryption key, the value itself will be returned.
    #
    # @param [String] encrypted_str Base64 encoded encrypted string with aes params (from `.encrypt`)
    # @param [String] secret_key 32 byte ASCII-8BIT encryption key
    # @return [String] decrypted string value
    def decrypt(encrypted_str, secret_key)
      return encrypted_str unless encrypted_str.is_a?(String) && secret_key
      return encrypted_str unless encrypted_str.start_with?(ENCRYPTED_PREFIX)

      if DELETE_PREFIX_SUPPORTED
        decrypt_str = encrypted_str.delete_prefix(ENCRYPTED_PREFIX)
      else
        decrypt_str = encrypted_str.sub(/\A#{Regexp.escape(ENCRYPTED_PREFIX)}/, "")
      end
      params = decode_aes(decrypt_str)

      cipher = OpenSSL::Cipher.new(CIPHER).decrypt

      cipher.key = secret_key
      cipher.iv = params.nonce
      cipher.auth_tag = params.auth_tag
      cipher.auth_data = ""

      decoded_str = cipher.update(params.data) + cipher.final

      # force to utf-8 encoding. We already ensured this when we encoded in the first place
      decoded_str.force_encoding('UTF-8')
    end

    private

    # format: <nonce:12>, <auth_tag:16>, <data:*>
    ENCODING_FORMAT = "a12 a16 a*"
    ENCRYPTED_PREFIX = "$AES$:"
    CIPHER = "aes-256-gcm"

    DELETE_PREFIX_SUPPORTED = "".respond_to?(:delete_prefix)
    private_constant :DELETE_PREFIX_SUPPORTED

    # Basic struct to contain nonce, auth_tag, and data for passing around. Thought
    # it was better than just passing an Array with positional params.
    # @private
    CipherParams = Struct.new(:nonce, :auth_tag, :data)

    # Receive a cipher object (initialized with key) and data
    def encode_aes(params)
      encoded = params.values.pack(ENCODING_FORMAT)
      # encode base64 and get rid of trailing newline and unnecessary =
      Base64.encode64(encoded).chomp.tr('=', '')
    end

    # Passed in an aes encoded string and returns a cipher object
    def decode_aes(str)
      unpacked_data = Base64.decode64(str).unpack(ENCODING_FORMAT)
      # Splat the data array apart
      # nonce, auth_tag, encrypted_data = unpacked_data
      CipherParams.new(*unpacked_data)
    end
  end

  # Parse a JSON stream or file with encrypted values. Any values in the ".encrypted" key
  # in the JSON document will be decrypted with the provided encryption key. If values
  # were put into the ".encrypted" key manually and are not yet encrypted, they will be used
  # as is without any decryption.
  #
  # @param [String, #read, Hash] path_or_stream path to a json/yaml file to load, an IO object, or a Hash (mostly for testing purposes)
  # @param [String] encryption_key secret to use for encryption/decryption
  #
  # @note If no encryption key is passed, this will defautl to env var SECRET_KEYS_ENCRYPTION_KEY
  def initialize(path_or_stream, encryption_key = nil)
    encryption_key = ENV['SECRET_KEYS_ENCRYPTION_KEY'] if encryption_key.nil? || encryption_key.empty?
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
  alias_method :to_hash, :to_h

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

  KDF_ITERATIONS = 20_000
  HASH_FUNC = 'sha256'
  KEY_LENGTH = 32

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
      hash = Marshal.load( Marshal.dump(path_or_stream) )
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
    (JSON.parse(data) rescue YAML.load(data))
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
    self.class.encrypt(value, @secret_key)
  end

  # Helper method to decrypt a value.
  def decrypt_value(encrypted_value)
    self.class.decrypt(encrypted_value, @secret_key)
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

  # Derive a key of given length from a password and salt value.
  def derive_key(password, salt:, length:)
    if defined?(OpenSSL::KDF)
      OpenSSL::KDF.pbkdf2_hmac(password, salt: salt, iterations: KDF_ITERATIONS, length: length, hash: HASH_FUNC)
    else
      OpenSSL::PKCS5.pbkdf2_hmac(password, salt, KDF_ITERATIONS, length, HASH_FUNC)
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
      # Convert the salt to raw byte string
      salt_bytes = [@salt].pack('H*')
      @secret_key = derive_key(@encryption_key, salt: salt_bytes, length: KEY_LENGTH)
    end
    # Don't accidentally return the secret, dammit
    nil
  end

end
