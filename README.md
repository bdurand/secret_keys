# SecretKeys

This ruby gem handles encrypting values in a JSON or YAML file. It is yet another solution for storing secrets in a ruby project.

The main advantage offered by this Gem is that it stores the files in standard JSON format and it can easily store both encrypted and non-encrypted values so you can store both your secrets and other configuration all in one place. It requires no special setup to access the encrypted data other than needing to provide the encryption key.

Encrypted values are salted and encrypted using a AES-128-ECB cipher with PBKDF2 hashing.

## Usage

You can load the JSON from a file

```ruby
secrets = SecretKeys.new("/path/to/file.json", "mysecretkey")
```

or a stream

```ruby
secrets = SecretKeys.new(File.open("/path/to/file.json"), "mysecretkey")
```

If you don't supply the encryption key in the constructor, it will be read from the `SECRET_KEYS_ENCRYPTION_KEY` environment variable.

The `SecretKeys` object delegates to hash and can be treated as a hash for most purposes.

```ruby
password = secrets["password"]
```

You can add values to the hash as well and move keys between the encrypted and unencrypted keys. The values are always stored unencrypted in memory, but you can save them to a JSON file.

```ruby
secrets["api_key"] = "1234567890"
secrets.encrypt!("api_key")
secrets.save("/path/to/file.json")
```

Note that since the hash must be serialized to JSON so only JSON compatible keys and values (string, number, boolean, null, array, hash) can be used.

Only string values can be encrypted. The encryption is recusive, so all strings in an array or hash in the encrypted keys will be encrypted.

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
  "key_1": "unencrypted value",
  ".encrypted": {
    ".key": "75E7B1F9F6B6CE3AC7FED8C30E886974eec820e8",
    "key_2": "362BD9D1C83D57E08CD1D7C0603780AF31c745ef",
  }
}
```
