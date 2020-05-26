# frozen_string_literal: true

require_relative "../spec_helper"
require_relative "../../lib/secret_keys/cli"

describe SecretKeys::CLI do
  describe SecretKeys::CLI::Base do
    describe "secret key options" do
      it "should set the secret key from the --secret-key option"
      it "should read the secret key from the --secret-key=- option"
      it "should read the secret key from the --secret-key-file option"
    end

    describe "output format option" do
      it "should set the output format from the --format option"
    end

    describe "input and output files" do
      it "should default to using STDIN and STDOUT"
      it "should use STDIN and STDOUT if set to -"
      it "should read the input from a file"
      it "should be able to set the output to a file"
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
