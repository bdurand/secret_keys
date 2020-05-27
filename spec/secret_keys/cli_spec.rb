# frozen_string_literal: true

require_relative "../spec_helper"
require_relative "../../lib/secret_keys/cli"

describe SecretKeys::CLI do
  let(:decrypted_file_path) { File.join(__dir__, "..", "fixtures", "decrypted.json") }
  let(:encrypted_file_path) { File.join(__dir__, "..", "fixtures", "encrypted.json") }
  let(:secret_key_path) { File.join(__dir__, "..", "fixtures", "secret_key") }

  around :each do |example|
    begin
      $stdin = StringIO.new("{}")
      example.call
    ensure
      $stdin = STDIN
    end
  end

  describe SecretKeys::CLI::Base do
    describe "secret key options" do
      it "should set the secret key from the --secret-key option" do
        command = SecretKeys::CLI::Base.new(["--secret-key", "foobar"])
        expect(command.secret_key).to eq "foobar"
      end

      it "should set the secret key from the -s option" do
        command = SecretKeys::CLI::Base.new(["-s", "foobar"])
        expect(command.secret_key).to eq "foobar"
      end

      it "should read the secret key from STDIN with the --secret-key=- option" do
        $stdin = StringIO.new("foobar")
        command = SecretKeys::CLI::Base.new(["--secret-key", "-"])
        expect(command.secret_key).to eq "foobar"
      end

      it "should read the secret key from the --secret-key-file option" do
        command = SecretKeys::CLI::Base.new(["--secret-key-file", secret_key_path])
        expect(command.secret_key).to eq "SECRET_KEY"
      end
    end

    describe "output format option" do
      it "should json as default" do
        command = SecretKeys::CLI::Base.new([])
        expect(command.format).to eq :json
      end

      it "should set the output format from the --format option" do
        command = SecretKeys::CLI::Base.new(["--format", "yaml"])
        expect(command.format).to eq :yaml
      end

      it "should set the output format from the output file extension" do
        command = SecretKeys::CLI::Base.new(["-", "/tmp/data.yml"])
        expect(command.format).to eq :yaml
      end

      it "should uset the default format from secrets input format if not specified" do
        command = SecretKeys::CLI::Base.new([])
        expect(command.secrets).to receive(:input_format).and_return(:yaml)
        expect(command.format).to eq :yaml
      end
    end

    describe "input and output files" do
      it "should default to using $stdin and $stdout" do
        command = SecretKeys::CLI::Base.new([])
        expect(command.input).to eq $stdin
        expect(command.output).to eq $stdout
      end

      it "should use $stdin and $stdout if set to -" do
        command = SecretKeys::CLI::Base.new(["-", "-"])
        expect(command.input).to eq $stdin
        expect(command.output).to eq $stdout
      end

      it "should set the input and output to file paths" do
        command = SecretKeys::CLI::Base.new([decrypted_file_path, "/tmp/out"])
        expect(command.input).to eq decrypted_file_path
        expect(command.output).to eq "/tmp/out"
      end
    end

    describe "output_stream" do
      it "should yield the output stream" do
        command = SecretKeys::CLI::Base.new(["-", "-"])
        command.output_stream do |stream|
          expect(stream).to eq $stdout
        end
      end

      it "should yield an stream to the output file" do
        out = Tempfile.new("secret_keys_cli_test")
        begin
          command = SecretKeys::CLI::Base.new(["-", out.path])
          command.output_stream do |stream|
            stream.write("foo")
          end
          expect(out.read).to eq "foo"
        ensure
          out.unlink
        end
      end
    end
  end

  describe SecretKeys::CLI::Encrypt do
    it "should encrypt the input file" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        command = SecretKeys::CLI::Encrypt.new(["--secret-key=SECRET_KEY", encrypted_file_path, temp_file.path])
        command.run!
        secrets = SecretKeys.new(temp_file.path, "SECRET_KEY")
        raw_json = JSON.parse(temp_file.read)
        expect(secrets["plaintext"]).to eq "not encrypted"
        expect(raw_json[SecretKeys::ENCRYPTED]).to include("plaintext")
        expect(raw_json[SecretKeys::ENCRYPTED]["plaintext"]).to_not eq secrets["plaintext"]
      ensure
        temp_file.unlink
      end
    end

    it "should encrypt the input file in place if the --in-place option is set" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        temp_file.write(File.read(encrypted_file_path))
        temp_file.rewind
        command = SecretKeys::CLI::Encrypt.new(["--secret-key=SECRET_KEY", "--in-place", temp_file.path])
        command.run!
        secrets = SecretKeys.new(temp_file.path, "SECRET_KEY")
        raw_json = JSON.parse(temp_file.read)
        expect(secrets["plaintext"]).to eq "not encrypted"
        expect(raw_json[SecretKeys::ENCRYPTED]).to include("plaintext")
        expect(raw_json[SecretKeys::ENCRYPTED]["plaintext"]).to_not eq secrets["plaintext"]
      ensure
        temp_file.unlink
      end
    end

    it "should encrypt the input file using a new encryption key" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        command = SecretKeys::CLI::Encrypt.new(["--secret-key=SECRET_KEY", "--new-secret-key=NEW_SECRET", encrypted_file_path, temp_file.path])
        command.run!
        secrets = SecretKeys.new(temp_file.path, "NEW_SECRET")
        expect(secrets["foo"]).to eq "bar"
      ensure
        temp_file.unlink
      end
    end
  end

  describe SecretKeys::CLI::Decrypt do
    it "should decrypt the input file" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        command = SecretKeys::CLI::Decrypt.new(["--secret-key=SECRET_KEY", encrypted_file_path, temp_file.path])
        command.run!
        json = JSON.parse(temp_file.read)
        expect(json).to eq JSON.parse(File.read(decrypted_file_path))
      ensure
        temp_file.unlink
      end
    end
  end

  describe SecretKeys::CLI::Read do
    it "should read a key from the input file" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        command = SecretKeys::CLI::Read.new(["--secret-key=SECRET_KEY", "--key=foo", encrypted_file_path, temp_file.path])
        command.run!
        value = temp_file.read
        expect(value).to eq "bar"
      ensure
        temp_file.unlink
      end
    end

    it "should read a nested key from the input file" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        command = SecretKeys::CLI::Read.new(["--secret-key=SECRET_KEY", "--key=complex.one", encrypted_file_path, temp_file.path])
        command.run!
        value = temp_file.read
        expect(value).to eq "value_1"
      ensure
        temp_file.unlink
      end
    end

    it "should not output anything if the key does not exist" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        command = SecretKeys::CLI::Read.new(["--secret-key=SECRET_KEY", "--key=complex.nothing", encrypted_file_path, temp_file.path])
        command.run!
        value = temp_file.read
        expect(value).to eq ""
      ensure
        temp_file.unlink
      end
    end
  end

  describe SecretKeys::CLI::Edit do
    it "should add a key to the encrypted keys" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--set-encrypted", "new=thing", encrypted_file_path, temp_file.path])
        command.run!
        secrets = SecretKeys.new(temp_file.path, "SECRET_KEY")
        expect(secrets["new"]).to eq "thing"
        expect(secrets.encrypted?("new")).to eq true
      ensure
        temp_file.unlink
      end
    end

    it "should move a key to the encrypted keys if it exists and no value was specified" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--set-encrypted", "not_encrypted", encrypted_file_path, temp_file.path])
        command.run!
        secrets = SecretKeys.new(temp_file.path, "SECRET_KEY")
        expect(secrets["not_encrypted"]).to eq "plain text value"
        expect(secrets.encrypted?("not_encrypted")).to eq true
      ensure
        temp_file.unlink
      end
    end

    it "should add a nested key to the encrypted keys" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--set-encrypted", "complex.four=four", encrypted_file_path, temp_file.path])
        command.run!
        secrets = SecretKeys.new(temp_file.path, "SECRET_KEY")
        expect(secrets["complex"]["four"]).to eq "four"
        expect(secrets.encrypted?("complex")).to eq true
      ensure
        temp_file.unlink
      end
    end

    it "should add a key to the plain text keys" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--set-decrypted", "new=thing", encrypted_file_path, temp_file.path])
        command.run!
        secrets = SecretKeys.new(temp_file.path, "SECRET_KEY")
        expect(secrets["new"]).to eq "thing"
        expect(secrets.encrypted?("new")).to eq false
      ensure
        temp_file.unlink
      end
    end

    it "should move a key to the plain text keys if it exists and no value was specified" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--set-decrypted", "foo", encrypted_file_path, temp_file.path])
        command.run!
        secrets = SecretKeys.new(temp_file.path, "SECRET_KEY")
        expect(secrets["foo"]).to eq "bar"
        expect(secrets.encrypted?("foo")).to eq false
      ensure
        temp_file.unlink
      end
    end

    it "should add a nested key to the plain text keys" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--set-decrypted", "thing.part=woot", encrypted_file_path, temp_file.path])
        command.run!
        secrets = SecretKeys.new(temp_file.path, "SECRET_KEY")
        expect(secrets["thing"]["part"]).to eq "woot"
        expect(secrets.encrypted?("thing")).to eq false
      ensure
        temp_file.unlink
      end
    end

    it "should remove a key from the encrypted keys" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--remove", "not_encrypted", encrypted_file_path, temp_file.path])
        command.run!
        secrets = SecretKeys.new(temp_file.path, "SECRET_KEY")
        expect(secrets).to_not include("not_encrypted")
      ensure
        temp_file.unlink
      end
    end

    it "should remove a key from the plain text keys" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--remove", "foo", encrypted_file_path, temp_file.path])
        command.run!
        secrets = SecretKeys.new(temp_file.path, "SECRET_KEY")
        expect(secrets).to_not include("foo")
      ensure
        temp_file.unlink
      end
    end
  end
end
