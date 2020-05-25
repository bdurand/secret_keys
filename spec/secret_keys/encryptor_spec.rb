# frozen_string_literal: true

require_relative "../spec_helper"

describe SecretKeys::Encryptor do
  it "should encrypt a value with a password an salt" do
    encryptor = SecretKeys::Encryptor.new("SECRET_KEY", "foo")
    encrypted = encryptor.encrypt("stuff")
    expect(encryptor.decrypt(encrypted)).to eq "stuff"
  end

  it "should never encrypt a value the same way twice" do
    encryptor = SecretKeys::Encryptor.new("SECRET_KEY", "foo")
    encrypted_1 = encryptor.encrypt("stuff")
    encrypted_2 = encryptor.encrypt("stuff")
    expect(encrypted_1).to_not eq encrypted_2
    expect(encryptor.decrypt(encrypted_2)).to eq "stuff"
  end

  it "should not encrypt a non-string" do
    encryptor = SecretKeys::Encryptor.new("SECRET_KEY", "foo")
    expect(encryptor.encrypt(1)).to eq 1
    expect(encryptor.encrypt(false)).to eq false
    expect(encryptor.encrypt(nil)).to eq nil
  end

  it "should not encrypt an empty string" do
    encryptor = SecretKeys::Encryptor.new("SECRET_KEY", "foo")
    expect(encryptor.encrypt("")).to eq ""
  end

  it "should not encrypt when the encryption key is nil" do
    encryptor = SecretKeys::Encryptor.new(nil, "foo")
    expect(encryptor.encrypt("foo")).to eq "foo"
  end
end
