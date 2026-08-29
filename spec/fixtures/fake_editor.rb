#!/usr/bin/env ruby
# frozen_string_literal: true

# Stand-in for $EDITOR in the CLI specs.
#
# Usage: fake_editor.rb MODE RECORD_FILE PATH
#
# Records the path of the temporary file it was given (and the modes of the file and its
# directory) in RECORD_FILE, then rewrites PATH according to MODE.
require "json"
require "yaml"

mode, record_file, path = ARGV
File.write(record_file, JSON.generate({
  "path" => path,
  "file_mode" => format("%o", File.stat(path).mode & 0o7777),
  "dir_mode" => format("%o", File.stat(File.dirname(path)).mode & 0o7777)
}))

yaml = path.end_with?(".yml", ".yaml")
data = yaml ? YAML.safe_load(File.read(path)) : JSON.parse(File.read(path))

case mode
when "noop"
  # Leave the file untouched.
when "fail"
  exit 3
when "invalid"
  File.write(path, "{ this is not valid JSON or YAML: [")
when "edit"
  encrypted = data[".encrypted"]
  # Change an encrypted value.
  encrypted["foo"] = "edited"
  # Add a new encrypted value.
  encrypted["new_secret"] = "shh"
  # Move a key out of the encrypted section and another one into it.
  data["plaintext"] = encrypted.delete("plaintext")
  encrypted["not_encrypted"] = data.delete("not_encrypted")
  File.write(path, yaml ? YAML.dump(data) : JSON.pretty_generate(data))
else
  abort "fake_editor.rb: unknown mode #{mode.inspect}"
end
