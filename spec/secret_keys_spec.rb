# frozen_string_literal: true

require_relative "spec_helper"

describe SecretKeys do
  let(:decrypted_file_path) { File.join(__dir__, "fixtures", "decrypted.json") }
  let(:encrypted_file_path) { File.join(__dir__, "fixtures", "encrypted.json") }
  let(:decrypted_values) { JSON.parse(File.read(decrypted_file_path)) }

  describe "class" do
    it "should behave as a Hash" do
      secrets = SecretKeys.new(nil, "SECRET_KEY")
      secrets["foo"] = "bar"
      expect(secrets["foo"]).to eq "bar"
      expect(secrets.size).to eq 1
      expect(secrets.to_a).to eq [["foo", "bar"]]
      expect(secrets.to_h).to eq({"foo" => "bar"})
      expect(secrets).to include(Enumerable)
    end
  end

  describe "loading keys" do
    let(:secrets) { SecretKeys.new(encrypted_file_path, "SECRET_KEY") }

    it "should load a JSON file with encrypted strings" do
      expect(secrets.to_h).to eq decrypted_values
    end

    it "should load a JSON stream with encrypted strings" do
      File.open(encrypted_file_path) do |json|
        secrets = SecretKeys.new(json, "SECRET_KEY")
        expect(secrets.to_h).to eq decrypted_values
      end
    end

    it "should load YAML with encrypted strings" do
      File.open(encrypted_file_path) do |json|
        data = JSON.parse(json.read)
        yaml = YAML.dump(data)
        secrets = SecretKeys.new(StringIO.new(yaml), "SECRET_KEY")
        expect(secrets.to_h).to eq decrypted_values
      end
    end

    it "should load a hash with encrypted strings" do
      File.open(encrypted_file_path) do |json|
        data = JSON.parse(json.read)
        secrets = SecretKeys.new(data, "SECRET_KEY")
        expect(secrets.to_h).to eq decrypted_values
      end
    end

    it "should not load keys if the encryption key doesn't match" do
      expect { SecretKeys.new(encrypted_file_path, "not_the_key") }.to raise_error(SecretKeys::EncryptionKeyError)
    end

    it "should load an unencrypted JSON file without an encryption key" do
      not_secret = SecretKeys.new(decrypted_file_path, nil)
      expect(not_secret.to_h).to eq secrets.to_h
    end

    it "should decrypt hash values" do
      expect(secrets["foo"]).to eq "bar"
    end

    it "should decrypt nested keys" do
      expect(secrets["array"]).to eq ["a", "b", "c"]
    end

    it "should not decrypt non-string keys" do
      expect(secrets["count"]).to eq 1
    end

    it "should not decrypt unencrypted values" do
      expect(secrets["plaintext"]).to eq "not encrypted"
    end

    it "should not include the encryption key in the decrypted secrets" do
      expect(secrets.include?(SecretKeys::ENCRYPTION_KEY)).to eq false
      expect(secrets.include?(SecretKeys::ENCRYPTED)).to eq false
    end
  end

  describe "#encrypted_hash" do
    it "should return the hash with encrypted values" do
      secrets = SecretKeys.new(encrypted_file_path, "SECRET_KEY")
      json = secrets.encrypted_hash

      expect(json).to_not include("foo")
      expect(json[SecretKeys::ENCRYPTED]).to include("foo")
      expect(json[SecretKeys::ENCRYPTED]["foo"]).to_not eq secrets["foo"]
      expect(json["not_encrypted"]).to eq secrets["not_encrypted"]

      decrypted = SecretKeys.new(StringIO.new(JSON.dump(json)), "SECRET_KEY")
      expect(decrypted.to_h).to eq decrypted_values
    end

    it "should re-encrypt with the new encryption key" do
      secrets = SecretKeys.new(encrypted_file_path, "SECRET_KEY")
      values = secrets.to_h
      secrets.encryption_key = "newkey"
      json = JSON.dump(secrets.encrypted_hash)
      new_secrets = SecretKeys.new(StringIO.new(json), "newkey")
      expect(new_secrets.to_h).to eq values
    end
  end

  describe "#encrypt!" do
    it "should add a key to the encrypted values" do
      secrets = SecretKeys.new(encrypted_file_path, "SECRET_KEY")
      secrets.encrypt!("not_encrypted")
      json = secrets.encrypted_hash
      expect(json).to_not include("not_encrypted")
      expect(json[SecretKeys::ENCRYPTED]).to include("not_encrypted")
      expect(json[SecretKeys::ENCRYPTED]["not_encrypted"]).to_not eq secrets["not_encrypted"]
    end
  end

  describe "#decrypt!" do
    it "should remove a key from the encrypted values" do
      secrets = SecretKeys.new(encrypted_file_path, "SECRET_KEY")
      secrets.decrypt!("foo")
      json = secrets.encrypted_hash
      expect(json).to include("foo")
      expect(json[SecretKeys::ENCRYPTED]).to_not include("foo")
      expect(json["foo"]).to eq secrets["foo"]
    end
  end

  describe "#save" do
    it "should save the encrypted hash as pretty JSON, only re-salting changed keys and encrypting unencrypted values" do
      tempfile = Tempfile.new(["secret_keys_test", ".json"])
      begin
        original_file_contents = File.read(encrypted_file_path)
        tempfile.write(original_file_contents)
        tempfile.flush

        secrets = SecretKeys.new(encrypted_file_path, "SECRET_KEY")
        secrets["foo"] = "new value"
        secrets.save(tempfile.path)
        tempfile.rewind

        original_json = JSON.parse(original_file_contents)[SecretKeys::ENCRYPTED]
        new_json = JSON.parse(tempfile.read)[SecretKeys::ENCRYPTED]

        original_json.each do |key, value|
          if key == "foo" || key == "plaintext"
            expect(value).to_not eq new_json[key]
          else
            expect(value).to eq new_json[key]
          end
        end
      ensure
        tempfile.close
      end
    end

    it "should save the encrypted hash as YAML, only re-salting changed keys and encrypting unencrypted values" do
      tempfile = Tempfile.new(["secret_keys_test", ".yml"])
      begin
        original_file_contents = File.read(encrypted_file_path)
        tempfile.write(original_file_contents)
        tempfile.flush

        secrets = SecretKeys.new(encrypted_file_path, "SECRET_KEY")
        secrets["foo"] = "new value"
        secrets.save(tempfile.path)
        tempfile.rewind

        original_yaml = YAML.safe_load(original_file_contents)[SecretKeys::ENCRYPTED]
        new_yaml = YAML.safe_load(tempfile.read)[SecretKeys::ENCRYPTED]

        original_yaml.each do |key, value|
          if key == "foo" || key == "plaintext"
            expect(value).to_not eq new_yaml[key]
          else
            expect(value).to eq new_yaml[key]
          end
        end
      ensure
        tempfile.close
      end
    end
  end

  describe "specifying encryption key" do
    it "should default to the value explicitly passed in" do
      ClimateControl.modify(SECRET_KEYS_ENCRYPTION_KEY: "nothing", SECRET_KEYS_ENCRYPTION_KEY_FILE: "/foo") do
        secrets = SecretKeys.new(encrypted_file_path, "SECRET_KEY")
        expect(secrets.to_h).to eq decrypted_values
      end
    end

    it "should read the encryption key from the SECRET_KEYS_ENCRYPTION_KEY environment variable" do
      ClimateControl.modify(SECRET_KEYS_ENCRYPTION_KEY: "SECRET_KEY", SECRET_KEYS_ENCRYPTION_KEY_FILE: "/foo") do
        secrets = SecretKeys.new(encrypted_file_path)
        expect(secrets.to_h).to eq decrypted_values
      end
    end

    it "should read the encryption key from the SECRET_KEYS_ENCRYPTION_KEY environment variable" do
      ClimateControl.modify(SECRET_KEYS_ENCRYPTION_KEY: "", SECRET_KEYS_ENCRYPTION_KEY_FILE: File.expand_path("fixtures/secret_key", __dir__)) do
        secrets = SecretKeys.new(encrypted_file_path)
        expect(secrets.to_h).to eq decrypted_values
      end
    end
  end
end
