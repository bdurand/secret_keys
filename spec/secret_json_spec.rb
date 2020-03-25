require_relative "spec_helper"

describe SecretJson do

  let(:decrypted_file_path) { File.join(__dir__, "fixtures", "decrypted.json") }
  let(:encrypted_file_path) { File.join(__dir__, "fixtures", "encrypted.json") }
  let(:decrypted_values) { JSON.load(File.read(decrypted_file_path)) }

  describe "class" do
    it "should behave as a Hash" do
      secrets = SecretJson.new(nil, "key")
      secrets["foo"] = "bar"
      expect(secrets["foo"]).to eq "bar"
      expect(secrets.size).to eq 1
      expect(secrets.to_a).to eq [["foo", "bar"]]
      expect(secrets.to_h).to eq({"foo" => "bar"})
      expect(secrets).to include(Enumerable)
    end
  end

  describe "loading JSON" do
    let(:secrets) { SecretJson.new(encrypted_file_path, "key") }

    it "should load a JSON file with encrypted strings" do
      expect(secrets.to_h).to eq decrypted_values
    end

    it "should load a JSON stream with encrypted strings" do
      File.open(encrypted_file_path) do |json|
        secrets = SecretJson.new(json, "key")
        expect(secrets.to_h).to eq decrypted_values
      end
    end

    it "should not load JSON if the encryption key doesn't match" do
      expect { SecretJson.new(encrypted_file_path, "not_the_key") }.to raise_error(ArgumentError)
    end

    it "should load an unencrypted JSON file without an encryption key" do
      not_secret = SecretJson.new(decrypted_file_path, nil)
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
      expect(secrets.include?(SecretJson::ENCRYPTION_KEY)).to eq false
      expect(secrets.include?(SecretJson::ENCRYPTED)).to eq false
    end
  end

  describe "encrypted_json" do
    it "should yield the JSON hash with encrypted values" do
      secrets = SecretJson.new(encrypted_file_path, "key")
      json = secrets.encrypted_json

      expect(json).to_not include("foo")
      expect(json[SecretJson::ENCRYPTED]).to include("foo")
      expect(json[SecretJson::ENCRYPTED]["foo"]).to_not eq secrets["foo"]
      expect(json["not_encrypted"]).to eq secrets["not_encrypted"]

      decrypted = SecretJson.new(StringIO.new(JSON.dump(json)), "key")
      expect(decrypted.to_h).to eq decrypted_values
    end

    it "should re-encrypt with the new encryption key" do
      secrets = SecretJson.new(encrypted_file_path, "key")
      values = secrets.to_h
      secrets.encryption_key = "newkey"
      json = JSON.dump(secrets.encrypted_json)
      new_secrets = SecretJson.new(StringIO.new(json), "newkey")
      expect(new_secrets.to_h).to eq values
    end
  end

  describe "encrypt!" do
    it "should add a key to the encrypted values" do
      secrets = SecretJson.new(encrypted_file_path, "key")
      secrets.encrypt!("not_encrypted")
      json = secrets.encrypted_json
      expect(json).to_not include("not_encrypted")
      expect(json[SecretJson::ENCRYPTED]).to include("not_encrypted")
      expect(json[SecretJson::ENCRYPTED]["not_encrypted"]).to_not eq secrets["not_encrypted"]
    end
  end

  describe "decrypt!" do
    it "should remove a key from the encrypted values" do
      secrets = SecretJson.new(encrypted_file_path, "key")
      secrets.decrypt!("foo")
      json = secrets.encrypted_json
      expect(json).to include("foo")
      expect(json[SecretJson::ENCRYPTED]).to_not include("foo")
      expect(json["foo"]).to eq secrets["foo"]
    end
  end

  describe "save" do
    it "should save the encrypted hash as pretty JSON, only re-salting changed keys and encrypting unencrypted values" do
      tempfile = Tempfile.new(["secret_json_test", ".json"])
      begin
        original_file_contents = File.read(encrypted_file_path)
        tempfile.write(original_file_contents)
        tempfile.flush

        secrets = SecretJson.new(encrypted_file_path, "key")
        secrets["foo"] = "new value"
        secrets.save(tempfile.path)
        tempfile.rewind

        original_json = JSON.load(original_file_contents)[SecretJson::ENCRYPTED]
        new_json = JSON.load(tempfile.read)[SecretJson::ENCRYPTED]

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
  end

  describe "encryption" do
    it "should encrypt a string with a salt" do
      encrypted_1 = SecretJson.encrypt("foo", "key")
      encrypted_2 = SecretJson.encrypt("foo", "key")
      expect(encrypted_1).to_not eq encrypted_2
      expect(SecretJson.decrypt(encrypted_1, "key")).to eq "foo"
      expect(SecretJson.decrypt(encrypted_2, "key")).to eq "foo"
    end

    it "should not encrypt a non-string" do
      expect(SecretJson.encrypt(1, "key")).to eq 1
      expect(SecretJson.encrypt(false, "key")).to eq false
      expect(SecretJson.encrypt(nil, "key")).to eq nil
    end

    it "should not encrypt when the encryption key is nil" do
      expect(SecretJson.encrypt("foo", nil)).to eq "foo"
    end
  end

end
