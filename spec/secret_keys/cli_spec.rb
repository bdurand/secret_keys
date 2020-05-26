# frozen_string_literal: true

require_relative "../spec_helper"
require_relative "../../lib/secret_keys/cli"

describe SecretKeys::CLI do
  let(:decrypted_file_path) { File.join(__dir__, "..", "fixtures", "decrypted.json") }
  let(:encrypted_file_path) { File.join(__dir__, "..", "fixtures", "encrypted.json") }
  let(:secret_key_path) { File.join(__dir__, "..", "fixtures", "secret_key") }

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
        stub_const("STDIN", StringIO.new("foobar"))
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
      it "should default to using STDIN and STDOUT" do
        command = SecretKeys::CLI::Base.new([])
        expect(command.input).to eq STDIN
        expect(command.output).to eq STDOUT
      end

      it "should use STDIN and STDOUT if set to -" do
        command = SecretKeys::CLI::Base.new(["-", "-"])
        expect(command.input).to eq STDIN
        expect(command.output).to eq STDOUT
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
          expect(stream).to eq STDOUT
        end
      end

      it "should yield an stream to the output file" do
        out = Tempfile.new("secret_keys_cli_test")
        command = SecretKeys::CLI::Base.new(["-", out.path])
        command.output_stream do |stream|
          stream.write("foo")
        end
        expect(out.read).to eq "foo"
      end
    end
  end

  describe SecretKeys::CLI::Encrypt do
    it "should encrypt the input file"

    it "should encrypt the input file using a new encryption key"

    it "should encrypt the input file in place if the --in-place option is set"
  end

  describe SecretKeys::CLI::Decrypt do
    it "should decrypt the input file"
  end

  describe SecretKeys::CLI::Read do
    it "should read a key from the input file"

    it "should read a nested key from the input file"

    it "should not output anything if the key does not exist"
  end

  describe SecretKeys::CLI::Edit do
    it "should add a key to the encrypted keys"

    it "should move a key to the encrypted keys if it exists and no value was specified"

    it "should add a nested key to the encrypted keys"

    it "should add a key to the plain text keys"

    it "should move a key to the plain text keys if it exists and no value was specified"

    it "should add a nested key to the plain text keys"

    it "should remove a key from the encrypted keys"

    it "should remove a key from the plain text keys"
  end
end
