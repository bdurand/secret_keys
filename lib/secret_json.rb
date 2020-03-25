# frozen_string_literal: true

require 'openssl'
require 'json'
require 'securerandom'
require 'delegate'
require 'set'
require 'pathname'
require 'base64'

# Load a JSON file with encrypted values. This value can be used as a hash.
class SecretJson < DelegateClass(Hash)

  ENCRYPTED = ".encrypted"
  ENCRYPTION_KEY = ".key"

  attr_writer :encryption_key

  class << self
    # Encrypt a string with the encryption key. Encrypted values are also salted so
    # calling this function multiple times will result in different values. Only strings
    # can be encrypted. Any other object type will be returned the value passed in.
    def encrypt(str, encryption_key, salt: nil)
      return str unless str.is_a?(String) && encryption_key

      salt ||= SecureRandom.hex(4)
      cipher = OpenSSL::Cipher.new('AES-128-ECB').encrypt
      cipher.key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(encryption_key, salt, 20_000, cipher.key_len)
      encrypted = cipher.update(str) + cipher.final
      "#{Base64.urlsafe_encode64(encrypted, padding: false)}|#{salt}"
    end

    # Decrypt a string with the encryption key. If the value is not a string or it was
    # not encrypted with the encryption key, the value itself will be returned.
    def decrypt(encrypted_str, encryption_key)
      return encrypted_str unless encrypted_str.is_a?(String) && encryption_key
      return encrypted_str unless encrypted_str.include?("|")

      desalted_encrypted_str, salt = encrypted_str.split("|", 2)
      cipher = OpenSSL::Cipher.new('AES-128-ECB').decrypt
      cipher.key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(encryption_key, salt, 20_000, cipher.key_len)
      begin
        decrypted = Base64.urlsafe_decode64(desalted_encrypted_str).unpack('C*').pack('c*')
        cipher.update(decrypted) + cipher.final
      rescue OpenSSL::Cipher::CipherError
        encrypted_str
      end
    end
  end

  # Parse a JSON stream or file with encrypted values. Any values in the ".encrypted" key
  # in the JSON document will be decrypted with the provided encryption key. If values
  # were put into the ".encrypted" key manually and are not yet encrypted, they will be used
  # as is without any decryption.
  def initialize(path_or_stream, encryption_key = nil)
    @encryption_key = (encryption_key || ENV['SECRET_JSON_KEY'])
    path_or_stream = (path_or_stream.is_a?(String) ? Pathname.new(path_or_stream) : path_or_stream)
    load_secrets!(path_or_stream)
    super(@values)
  end

  # Convert the value into an actual Hash object.
  def to_h
    @values
  end
  alias_method :to_hash, :to_h

  # Mark the key as being encrypted when the JSON is saved.
  def encrypt!(key)
    @secret_keys << key
  end

  # Mark the key as no longer being decrypted when the JSON is saved.
  def decrypt!(key)
    @secret_keys.delete(key)
  end

  # Return true if the key is encrypted.
  def encrypted?(key)
    @secret_keys.include?(key)
  end

  # Save the JSON to a file at the specified path. Encrypted values in the file
  # will not be re-salted if the values have not changed.
  def save(path)
    encrypted = encrypted_json

    if File.exist?(path)
      original_hash = JSON.load(File.read(path))
      original_encrypted = original_hash[ENCRYPTED] if original_hash
      if original_encrypted
        restore_unchanged_keys!(encrypted[ENCRYPTED], original_encrypted)
      end
    end

    File.open(path, "w") do |file|
      file.write(JSON.pretty_generate(encrypted))
      file.write($/)
    end
    nil
  end

  # Output the JSON structure as a hash with all encrypted values being encrypted using.
  # This is the same structure that can be loaded by the initalizer.
  #
  # Note that all encrypted values will be re-salted when they are encrypted.
  def encrypted_json
    raise ArgumentError.new("Encryption key not specified") if @encryption_key.nil? || @encryption_key.empty?

    hash = {}
    encrypted = {}
    @values.each do |key, value|
      if @secret_keys.include?(key)
        encrypted[key] = value
      else
        hash[key] = value
      end
    end
    encrypted = {ENCRYPTION_KEY => encrypt_value(@encryption_key)}.merge(encrypt_values(encrypted))

    hash[ENCRYPTED] = encrypted
    hash
  end

  private

  # Load the JSON data in a file path or stream into a hash, decrypting all the encrypted values.
  def load_secrets!(path_or_stream)
    @secret_keys = Set.new
    @values = {}

    hash = JSON.load(path_or_stream.read) unless path_or_stream.nil?
    return if hash.nil? || hash.empty?

    encrypted_values = hash.delete(ENCRYPTED)
    if encrypted_values
      file_key = encrypted_values.delete(ENCRYPTION_KEY)
      if file_key && !encryption_key_matches?(file_key)
        raise ArgumentError.new("Incorrect encryption key")
      end
      @secret_keys = encrypted_values.keys
      hash.merge!(decrypt_values(encrypted_values))
    end

    @values = hash
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
      values.keys.each do |key|
        decrypted_hash[key.to_s] = decrypt_values(values[key])
      end
      decrypted_hash
    elsif values.is_a?(Enumerable)
      values.collect { |value| decrypt_values(value) }
    else
      decrypt_value(values)
    end
  end

  # Since the encrypted values include a salt, make sure we don't overwrite values in the JSON
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
    self.class.encrypt(value, @encryption_key)
  end

  # Helper method to decrypt a value.
  def decrypt_value(encrypted_value)
    self.class.decrypt(encrypted_value, @encryption_key)
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

  def encryption_key_matches?(encrypted_key)
    decrypt_value(encrypted_key) == @encryption_key
  end

end
