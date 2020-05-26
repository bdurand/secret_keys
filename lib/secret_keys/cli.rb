# frozen_string_literal: true

require "optparse"
require "io/console"

require_relative "../secret_keys.rb"

module SecretKeys::CLI
  class Base
    attr_reader :secrets

    def initialize(argv)
      parse_options(argv)
      @secrets = SecretKeys.new(@input, @secret_key)
    end

    # Subclasses can override this method to parse additional options beyond the standard set.
    def parse_additional_options(opts)
    end

    # Subclasses must implement this method to execute the logic.
    def run
      raise NotImplementedError
    end

    # This method should be called when referencing the output stream. It will yield to the
    # block with a stream.
    def with_output_stream
      if @output.respond_to?(:write)
        yield(@output)
        @output.flush
      else
        File.open(@output, "w") do |file|
          yield(file)
        end
      end
      nil
    end

    private

    def parse_options(argv)
      @secret_key = nil
      @format = nil

      OptionParser.new do |opts|
        opts.banner = "Usage: secret_keys <encrypt|decrypt|read|edit> [options] [--] INFILE [OUTFILE|-]"

        opts.on("--help", "Prints this help") do
          puts opts.help
          exit
        end

        opts.on("-s", "--secret-key ENCRYPTION_KEY", String, "Encryption key used to encrypt strings in the file. This value can also be passed in the SECRET_KEYS_ENCRYPTION_KEY environment variable or via STDIN by specifying -.") do |value|
          @secret_key = get_secret_key(value)
        end

        opts.on("--secret-key-file ENCRYPTION_KEY_FILE_PATH", String, "Path to a file that contains the encryption key. This value can also be passed in the SECRET_KEYS_ENCRYPTION_KEY environment variable.") do |value|
          @secret_key = File.read(value).chomp
        end

        opts.on("-f", "--format [FORMAT]", [:json, :yaml, :auto], "Set the output format. By default this will be the same as the input format.") do |value|
          @format = get_format(value)
        end

        parse_additional_options(opts)
      end.order!(argv)

      raise ArgumentError.new("Too many arguments") if argv.size > 2
      @input = argv.shift
      @input = STDIN if @input == "-"

      @output = argv.first
      @output = STDOUT if @output.nil? || output == "-"
    end

    def get_secret_key(value)
      if value == "-"
        if STDIN.tty?
          STDIN.getpass("Secret key: ")
        else
          STDIN.gets
        end
      else
        value
      end
    end

    def get_format(value)
      if value.downcase == "json"
        :json
      elsif value.downcase == "yaml"
        :yaml
      else
        raise ArgumentError.new("format must be either YAML or JSON")
      end
    end
  end

  class Encrypt < Base
    def parse_additional_options(opts)
      @new_secret_key = nil
      opts.on("--new-secret-key ENCRYPTION_KEY", String, "Encryption key used to encrypt strings in the file on output. This option can be used to change the encryption key.") do |value|
        @new_secret_key = value
      end

      @in_place = false
      opts.on("--in-place", "Update the input file instead of writing to an output file.") do |value|
        @in_place = true
      end
    end

    def run
    end
  end

  class Decrypt < Base
    def run
    end
  end

  class Read < Base
    def parse_additional_options(opts)
      @key = nil
      opts.on("-k", "--key KEY", String, "Key from the file to output. You can use dot notation to read a nested key.") do |value|
        @key = value
      end
    end

    def run
      raise ArgumentError.new("key is required") if @key.nil? || @key.empty?
      val = secrets.to_h
      @key.split(".").each do |key|
        val = secrets[key] if val.is_a?(Hash)
      end
      val
    end
  end

  class Edit < Base
    def parse_additional_options(opts)
      @actions = []
      opts.on("-e", "--set-encrypted KEY[=VALUE]", String, "Set an encrypted value in the file. You can use dot notation to set a nested value. If no VALUE is specified, the key will be moved to the encrypted keys while keeping any existing value.") do |value|
        key, val = value.split("=", 2)
        @actions << [:encrypt, key, val]
      end
      opts.on("-d", "--set-decrypted KEY[=VALUE]", String, "Set a plain text value in the file. You can use dot notation to set a nested value. If no VALUE is specified, the key will be moved to the plain text keys while keeping any existing value.") do |value|
        key, val = value.split("=", 2)
        @actions << [:decrypt, key, val]
      end
      opts.on("-r", "--remove KEY", String, "Remove a key from the file. You can use dot notation to remove a nested value.") do |value|
        @actions << [:remove, value]
      end
    end

    def run
    end
  end
end
