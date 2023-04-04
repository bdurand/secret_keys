# frozen_string_literal: true

require_relative "../spec_helper"

describe SecretKeys::Encryptor do
  let(:password) { "SECRET_KEY" }
  let(:salt) { "deadbeef" }
  let(:encryptor) { SecretKeys::Encryptor.from_password(password, salt) }

  describe "#encrypt" do
    it "should encrypt a value with a password an salt" do
      encrypted = encryptor.encrypt("stuff")
      expect(encryptor.decrypt(encrypted)).to eq "stuff"
    end

    it "should encode data without linefeeds or padding" do
      long_line = "Hello, world!" * 100
      encrypted = encryptor.encrypt(long_line)
      expect(encrypted).to_not include "="
      expect(encrypted).to_not include "\n"
      expect(encryptor.decrypt(encrypted)).to eq long_line
    end

    it "should never encrypt a value the same way twice" do
      encrypted_1 = encryptor.encrypt("stuff")
      encrypted_2 = encryptor.encrypt("stuff")
      expect(encrypted_1).to_not eq encrypted_2
      expect(encryptor.decrypt(encrypted_2)).to eq "stuff"
    end

    it "should not encrypt a non-string" do
      expect(encryptor.encrypt(1)).to eq 1
      expect(encryptor.encrypt(false)).to eq false
      expect(encryptor.encrypt(nil)).to eq nil
    end

    it "should not encrypt an empty string" do
      encryptor = SecretKeys::Encryptor.from_password("SECRET_KEY", "deadbeef")
      expect(encryptor.encrypt("")).to eq ""
    end
  end

  describe ".from_password" do
    it "should raise an error if password is empty" do
      expect { SecretKeys::Encryptor.from_password(nil, salt) }.to raise_error(ArgumentError)
      expect { SecretKeys::Encryptor.from_password("", salt) }.to raise_error(ArgumentError)
    end

    it "should raise an error if salt is invalid" do
      expect { SecretKeys::Encryptor.from_password(password, nil) }.to raise_error(ArgumentError)
      expect { SecretKeys::Encryptor.from_password(password, "") }.to raise_error(ArgumentError)
      expect { SecretKeys::Encryptor.from_password(password, "d") }.to raise_error(ArgumentError)
      expect { SecretKeys::Encryptor.from_password(password, "nothex") }.to raise_error(ArgumentError)
    end
  end

  describe ".new" do
    it "should raise an error if key is incorrect length" do
      expect { SecretKeys::Encryptor.new("too_short") }.to raise_error(ArgumentError)
    end
  end

  describe ".encrypted?" do
    it "should determine if a value is encrypted" do
      encryptor = SecretKeys::Encryptor.from_password("key", "00000000")
      encrypted_value = encryptor.encrypt("foobar")
      expect(SecretKeys::Encryptor.encrypted?(encrypted_value)).to eq true
      expect(SecretKeys::Encryptor.encrypted?("foobar")).to eq false
    end
  end
end
