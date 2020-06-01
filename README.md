# SecretKeys

[![specs](https://github.com/bdurand/secret_keys/workflows/Run%20tests/badge.svg)](https://github.com/bdurand/secret_keys/actions?query=branch%3Amaster)
[![code style](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://github.com/testdouble/standard)
[![gem version](https://badge.fury.io/rb/secret_keys.svg)](https://badge.fury.io/rb/secret_keys)

This ruby gem handles encrypting values in a JSON or YAML file. It is yet another solution for storing secrets in a ruby project.

The main advantage offered by this gem is that it stores the files in standard JSON or YAML format and can store both encrypted and non-encrypted values side-by-side, easily tracking all your configurations in one place. After providing your secret key, all values can be easily accessed regardless of whether they were encrypted or plaintext.

Encrypted values are stored using AES-256-GCM, and the key is derived from your password secret and a generated salt using PBKDF2. All security primitives are provided by OpenSSL, based on recommendations put forth in the [libsodium](https://doc.libsodium.org/secret-key_cryptography/aead/aes-256-gcm) crypto suite.

## Usage

You can load the JSON/YAML from a file

```ruby
secrets = SecretKeys.new("/path/to/file.json", "mysecretkey")
```

or a stream

```ruby
stream = File.open("/path/to/file.json")
secrets = SecretKeys.new(stream, "mysecretkey")
stream.close
```

If you don't supply the encryption key in the constructor, by it will be read from the `SECRET_KEYS_ENCRYPTION_KEY` environment variable. If that value is not present, then it will attempt to be read from the file path in the `SECRET_KEYS_ENCRYPTION_KEY_FILE` environment variable. As a side note, the empty string `""` is not considered a valid secret, so encryption **will** fail if there is no explicitly passed secret and no `ENV` variables.

The `SecretKeys` object delegates to `Hash` and can be treated as a hash for most purposes.

```ruby
password = secrets["password"]
```

You can add values to the hash as well and move keys between being encrypted/unencrypted at rest. The values are always stored unencrypted in memory, but you can save them to a JSON or YAML file.

```ruby
# api_key is plaintext by default
secrets["api_key"] = "1234567890"

# mark api_key as a secret to encrypt
secrets.encrypt!("api_key")

# now, when we save, the value for api_key is encrypted
secrets.save("/path/to/file.json")

# or get a Hash with the encrypted data to handle it yourself
secrets.encrypted_hash
```

Note that since the hash must be serialized to JSON, only JSON compatible keys and values (string, number, boolean, null, array, hash) can be used. The same holds for YAML. All keys must be strings.

**Only string values are encrypted**. The encryption is recursive, so all strings in an array or hash in the encrypted keys will be encrypted. See the example below.

```javascript
{
  ".encrypted": {
    "enc_key1": {
      "num": 1, // primitives are not encrypted
      "null_value": null, // null is not encrypted
      "rec": [
        "<encrypted-val>", // we recurse through the array to encrypt its strings
        true // booleans aren't encrypted either
      ],
      "thing": "<encrypted-val>"
    },
    "enc_key2": "<encrypted-val>"
  },
  "unenc_key": "plaintext",
  "other_plaintext": "See, you can read my contents!"
}
```

## Command Line Tool

You can use the `secret_keys` command line tool to manage your JSON files.

```console
$ secret_keys help
Usage: secret_keys <command> ...

Commands:
    encrypt   Encrypt a file
    decrypt   Decrypt a file
    read      Read the value of one key in a file
    edit      Change which values are encrypted, the file's encryption key, delete/add keys, etc.
    init      Initialize an empty secrets file

    help      Get help for a command
```

You can initialize a new file with the init command.

```bash
secret_keys init --secret=mysecret /path/to/new/file.json
```

Or add the encryption section to an existing file.

```bash
secret_keys encrypt --secret=mysecret --in-place /path/to/file.json
```

You can also specify the path to a file where the secret is stored with `--secret-file`. If you don't specify the `--secret` or `--secret-file` argument, the secret will be read from the `SECRET_KEYS_ENCRYPTION_KEY` or `SECRET_KEYS_ENCRYPTION_KEY_FILE` environment variable.

You can also specify to read the secret from STDIN with `--secret=-`.

```bash
# reading from stdin
$ secret_keys encrypt --secret=- data.json
Secret Key: <hidden password input>

# or you can pipe in the secret
$ echo "my_secret" | secret_keys encrypt --secret=- data.json
```

You can then use your favorite text editor to edit the values in the file and putting any keys you want encrypted in the `".encrypted"` section. When you are done, you can run the same command again to encrypt all new keys in the file. The default behaviour is to output the file to STDOUT, or you can rewrite the file in place by passing `--in-place`.

Finally, calling encrypt with `--encrypt-all` will encrypt all keys in a file. You can use this to encrypt all the values in an existing JSON or YAML file.

```bash
secret_keys encrypt -s mysecret --encrypt-all --in-place data.json
```

You can also add or modify keys through the command line using `--set-encrypted` or `-e` for short. You can also use "dot syntax" to address nested keys, for example `aws.client_secret` addresses `{"aws":{"client_secret": <value>}}`

```console
# mark individual keys for encryption
$ secret_keys edit -s mysecret --set-encrypted password -e other_password /path/to/file.json
{ ... }

# add an encrypted key with a value
$ secret_keys edit -s mysecret --set-encrypted password=value /path/to/file.json
{ ... }

# edit nested keys (assumes hashes by default)
# nested keys are split on `.` dots
$ secret_keys edit -s mysecret -e aws.secret=password data.json
{
  ".encrypted": {
    "aws": {
      "secret": "<encrypted-value>"
    },
    ...
  }
}
```

You can also decrypt keys by moving them to the plain text section of the file (`--set-decrypted` or `-d`) or remove them altogether (`--remove` or `-r`).

```bash
secret_keys edit -s mysecret --set-decrypted username --remove password /path/to/file.json
```

You can change the encryption key used in the file.

```bash
secret_keys encrypt -s mysecret --new-secret-key newsecret /path/to/file.json
```

Finally, you can print the unencrypted file to STDOUT.

```bash
# print the decrypted file to stdout
secret_keys decrypt --secret mysecret /path/to/file.json

# Explicitly output as JSON
secret_keys decrypt --secret mysecret --format json /path/to/file.json

# Output the data as YAML
secret_keys decrypt --secret mysecret --format yaml /path/to/file.json
```

## File Format

The data can be stored in a plain old JSON or YAML file. Any unencrypted keys will appear under the special `".encrypted"` key in the hash. A check value (to validate you are using the correct encryption key) is stored under `".key"`. Finally, there is also the `".salt"` which was used for key derivation.

In this example, `not_encrypted` is stored in plain text while `foo` has been encrypted.

```json
{
  ".encrypted": {
    ".salt": "aecdfdb296983ec0",
    ".key": "$AES$:LNkaWu/g7gM7zu4qC/4FAGOANOLWcY86uqxQfFiHRVSvXSA23pY",
    "foo": "$AES$:XcbGIW9ABbfcMv79+YK0MC8P7WWtEAfE2Y8S/MMN5Q",
    "array": [
      "$AES$:1WPr25fkbVbQWvTCiEHJOPT50970Z+D8qkYTnTk",
      "$AES$:FgSCK3pG8RBtYFqzO/WmNwus2SABI5zGGmfkPEw"
    ],
  },
  "not_encrypted": "plain text value"
}
```

## SecretKeys::Encryptor

This library also comes with a generic encryption tool that can be used on its own as a generic tool for encrypting strings with AES-256-GCM encryption.

```ruby
secret = "mysecret"
# The salt is used to generate an encryption key from the secret.
# You do not need to salt individual values when encrypting them.
# This will be done by the encryption algorithm itself.
# The salt must be a hex encoded byte array.
salt = "deadbeef"

encryptor = SecretKeys::Encryptor.from_passowrd(secret, salt)

encrypted = encryptor.encrypt("foobar") # => "$AES$:345kjwertE345E..."
encryptor.decrypt(encrypted) # => "foobar"
encryptor.decrypt("foobar") # => "foobar"

# If the data is corrupted/tampered with, decryption will raise an error.
# This can also be caused by using the wrong key.
begin
  encryptor.decrypt("$AES$:malformed/corrupted data")
rescue OpenSSL::Cipher::CipherError
  puts "Bad data/encryption key"
end

# You can also check if a value looks like an encrypted string.
SecretKeys::Encryptor.encrypted?("foobar") # => false
SecretKeys::Encryptor.encrypted?(encrypted) # => true
```

## Versioning

This code aims to be compliant with [Semantic Verioning 2.0](https://semver.org/). If there is ever a need to change file encryption parameters, those changes will be released as a new major version. Just to be clear, we do not anticipate needing to change these parameters.
