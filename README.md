# SecretKeys

This ruby gem handles encrypting values in a JSON or YAML file. It is yet another solution for storing secrets in a ruby project.

The main advantage offered by this gem is that it stores the files in standard JSON format and it can easily store both encrypted and non-encrypted values side-by-side, so easily track all your configurations in one place. After providing your secret key, all values can be easily accessed regardless of whether they were encrypted or plaintext.

Encrypted values are stored using aes-256-gcm, and the key is derived from your password secret and salt using PBKDF2. All security primitives are provided by openssl, based on recommendations put forth in the libsodium crypto suite.

## Usage

You can load the JSON/YAML from a file

```ruby
secrets = SecretKeys.new("/path/to/file.json", "mysecretkey")
```

or a stream

```ruby
secrets = SecretKeys.new(File.open("/path/to/file.json"), "mysecretkey")
```

If you don't supply the encryption key in the constructor, by default it will be read from the `SECRET_KEYS_ENCRYPTION_KEY` environment variable. If that value is not present, then it will attempted to be read from the file path in the `SECRET_KEYS_ENCRYPTION_KEY_FILE` environment variable. As a side note, the empty string (`""`) is not considered a valid secret, so encryption **will** fail if ther is no explicitly passed secret and no ENV variable.

The `SecretKeys` object delegates to `Hash` and can be treated as a hash for most purposes.

```ruby
password = secrets["password"]
```

You can add values to the hash as well and move keys between being encrypted/unencrypted at rest. The values are always stored unencrypted in memory, but you can save them to a JSON file.

```ruby
# api_key is plaintext by default
secrets["api_key"] = "1234567890"

# mark api_key as a secret to encrypt
secrets.encrypt!("api_key")

# now, when we save, the value for api_key is encrypted
secrets.save("/path/to/file.json")
```

Note that since the hash must be serialized to JSON, only JSON compatible keys and values (string, number, boolean, null, array, hash) can be used. The same holds for YAML.

Only string values can be encrypted. The encryption is recusive, so all strings in an array or hash in the encrypted keys will be encrypted. See the example below.

```json
{
  ".encrypted": {
    "enc_key1": {
      "num": 1,
      "rec": ["<encrypted-val>", true],
      "thing": "<encrypted-val>"
    },
    "enc_key2": "<encrypted-val>"
  },
  "unenc_key": "plaintext"
}
```

## Command Line Tool

You can use the `secret_keys` command line tool to manage your JSON files.

You can initialize a new file with the encrypt command.

```bash
secret_keys encrypt --key mysecret /path/to/file.json
```

If you don't specify the `--key` argument, the encryption key will either be read from the STDIN stream or from the `SECRET_KEYS_ENCRYPTION_KEY` environment variable.

You can then use your favorite text editor to edit the values in the JSON file. When you are done, you can run the same command again to encrypt the file.

You can add or modify keys through the command line as well.

```bash
# add an encrypted key
secret_keys encrypt --key mysecret --set password /path/to/file.json

# add an encrypted key with a value
secret_keys encrypt --key mysecret --set password=value /path/to/file.json

# encrypt all keys in the file
secret_keys encrypt --key mysecret --all /path/to/file.json
```

You can also decrypt or delete keys.

```bash
secret_keys encrypt --key mysecret --decrypt username --delete password /path/to/file.json
```

You can change the encryption key used in the file.

```bash
secret_keys encrypt --key mysecret --new-key newsecret /path/to/file.json
```

Finally, you can print the unencrypted file to STDOUT.

```bash
secret_keys decrypt --key mysecret /path/to/file.json
```

## File Format

The data can be stored in a plain old JSON file. Any unencrypted keys will appear under in the special `".encrypted"` key in the hash. The encryption key itself is also stored in the `".key"` key along with the encrypted values. This is used to confirm that the correct key is being used when decrypting the file.

In this example, `key_1` is stored in plain text while `key_2` has been encrypted.

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
