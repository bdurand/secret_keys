# frozen_string_literal: true

# Logic handling encryption and description using encryption key derived from the secret key.
class SecretKeys::Encryptor
  # format: <nonce:12>, <auth_tag:16>, <data:*>
  ENCODING_FORMAT = "a12 a16 a*"
  ENCRYPTED_PREFIX = "$AES$:"
  CIPHER = "aes-256-gcm"
  KDF_ITERATIONS = 20_000
  HASH_FUNC = "sha256"
  KEY_LENGTH = 32

  # @param [String] secret password used to encrypt the data
  # @param [String] random salt used in encryption
  def initialize(password, salt)
    # Convert the salt to raw byte string
    salt_bytes = [salt].compact.pack("H*")
    @derived_key = nil
    if password && !password.empty?
      @derived_key = derive_key(password, salt: salt_bytes, length: KEY_LENGTH)
    end
  end

  # Encrypt a string with the encryption key. Encrypted values are also salted so
  # calling this function multiple times will result in different values. Only strings
  # can be encrypted. Any other object type will be returned the value passed in.
  #
  # @param [String] str string to encrypt (assumes UTF-8)
  # @return [String] Base64 encoded encrypted string with all aes parameters
  def encrypt(str)
    return str unless str.is_a?(String) && @derived_key
    return "" if str == ""

    cipher = OpenSSL::Cipher.new(CIPHER).encrypt

    # Technically, this is a "bad" way to do things since we could theoretically
    # get a repeat nonce, compromising the algorithm. That said, it should be safe
    # from repeats as long as we don't use this key for more than 2^32 encryptions
    # so... rotate your keys/salt ever 4 billion encryption calls
    nonce = cipher.random_iv
    cipher.key = @derived_key
    cipher.auth_data = ""

    # Make sure the string is encoded as UTF-8. JSON/YAML only support string types
    # anyways, so if you passed in binary data, it was gonna fail anyways. This ensures
    # that we can easily decode the string later. If you have UTF-16 or something, deal with it.
    utf8_str = str.encode(Encoding::UTF_8)
    encrypted_data = cipher.update(utf8_str) + cipher.final
    auth_tag = cipher.auth_tag

    params = CipherParams.new(nonce, auth_tag, encrypted_data)

    encode_aes(params).prepend(ENCRYPTED_PREFIX)
  end

  # Decrypt a string with the encryption key. If the value is not a string or it was
  # not encrypted with the encryption key, the value itself will be returned.
  #
  # @param [String] encrypted_str Base64 encoded encrypted string with aes params (from `.encrypt`)
  # @return [String] decrypted string value
  def decrypt(encrypted_str)
    return encrypted_str unless encrypted_str.is_a?(String) && @derived_key
    return encrypted_str unless encrypted_str.start_with?(ENCRYPTED_PREFIX)

    decrypt_str = encrypted_str[ENCRYPTED_PREFIX.length..-1]
    params = decode_aes(decrypt_str)

    cipher = OpenSSL::Cipher.new(CIPHER).decrypt

    cipher.key = @derived_key
    cipher.iv = params.nonce
    cipher.auth_tag = params.auth_tag
    cipher.auth_data = ""

    decoded_str = cipher.update(params.data) + cipher.final

    # force to utf-8 encoding. We already ensured this when we encoded in the first place
    decoded_str.force_encoding(Encoding::UTF_8)
  end

  private

  # Basic struct to contain nonce, auth_tag, and data for passing around. Thought
  # it was better than just passing an Array with positional params.
  # @private
  CipherParams = Struct.new(:nonce, :auth_tag, :data)

  # Receive a cipher object (initialized with key) and data
  def encode_aes(params)
    encoded = params.values.pack(ENCODING_FORMAT)
    # encode base64 and get rid of trailing newline and unnecessary =
    Base64.encode64(encoded).chomp.tr("=", "")
  end

  # Passed in an aes encoded string and returns a cipher object
  def decode_aes(str)
    unpacked_data = Base64.decode64(str).unpack(ENCODING_FORMAT)
    # Splat the data array apart
    # nonce, auth_tag, encrypted_data = unpacked_data
    CipherParams.new(*unpacked_data)
  end

  # Derive a key of given length from a password and salt value.
  def derive_key(password, salt:, length:)
    if defined?(OpenSSL::KDF)
      OpenSSL::KDF.pbkdf2_hmac(password, salt: salt, iterations: KDF_ITERATIONS, length: length, hash: HASH_FUNC)
    else
      OpenSSL::PKCS5.pbkdf2_hmac(password, salt, KDF_ITERATIONS, length, HASH_FUNC)
    end
  end
end
