# frozen_string_literal: true

require "optparse"
require "io/console"

require_relative "../secret_keys.rb"

module SecretKeys::CLI
  class Base
    attr_reader :secret_key, :input

    MAX_SUMMARY_LENGTH = 80

    def initialize(argv)
      # make sure we can only use stdin once
      @stdin_used = false
      @secrets = nil
      parse_options(argv)
    end

    # Subclasses can override this method to parse additional options beyond the standard set.
    def parse_additional_options(opts)
    end

    # @return [SecretKeys] the secrets
    def secrets
      @secrets ||= SecretKeys.new(@input, @secret_key)
    end

    # Subclasses should return the action name for the help banner
    def action_name
      "<encrypt|decrypt|read|edit>"
    end

    # Subclasses must implement this method to execute the logic.
    def run!
      raise NotImplementedError
    end

    # Return the output format.
    def format
      return @format if [:json, :yaml].include?(@format)
      secrets.input_format
    end

    protected

    def encrypted_file_contents
      encrypted = secrets.encrypted_hash
      string = (format == :yaml ? YAML.dump(encrypted) : JSON.pretty_generate(encrypted))
      string << $/ unless string.end_with?($/) # ensure file ends with system dependent new line
      string
    end

    private

    def parse_options(argv)
      @secret_key = nil
      @format = nil

      OptionParser.new do |opts|
        opts.banner = "Usage: secret_keys #{action_name} [options] [--] [INFILE|-]"

        opts.separator("\nGlobal options:")

        secret_docs = split(<<~HELP)
          Encryption key used to encrypt strings in the file.
          This value can also be passed in the SECRET_KEYS_ENCRYPTION_KEY environment variable or via STDIN by specifying '-'.
        HELP
        opts.on("-s", "--secret-key=SECRET", String, *secret_docs) do |value|
          raise ArgumentError, "You have already passed in the secret key" unless @secret_key.nil?
          @secret_key = get_secret_key(value)
        end

        secret_file_docs = split(<<~HELP)
          Path to a file that contains the encryption key.
          This value can also be passed in the SECRET_KEYS_ENCRYPTION_KEY_FILE environment variable.
        HELP
        opts.on("--secret-key-file=PATH", String, *secret_file_docs) do |value|
          raise ArgumentError, "You have already passed in the secret key" unless @secret_key.nil?
          @secret_key = File.read(value).chomp
        end

        opts.on("-f", "--format FORMAT", [:json, :yaml], "Set the output format. By default this will be the same as the input format.") do |value|
          @format = value
        end

        opts.on("-h", "--help", "Prints this help") do
          puts opts.help
          exit
        end

        parse_additional_options(opts)
      end.order!(argv)

      @input = argv.shift
      if @input.nil? || @input == "-"
        can_i_haz_stdin!
        @input = $stdin
      end

      raise ArgumentError.new("Too many arguments") unless argv.empty?
    end

    def get_secret_key(value)
      if value == "-"
        can_i_haz_stdin!
        if $stdin.tty?
          $stdin.getpass("Secret key: ")
        else
          $stdin.gets.chomp
        end
      else
        value
      end
    end

    # @return [Array] array of strings from docstring, split at length
    def split(docstring, length: MAX_SUMMARY_LENGTH)
      docstring = docstring.strip
      docstring.gsub!(/\s+/, " ")
      docstring.scan(/(.{1,#{length}})(?:\s+|\z)/).flatten
    end

    # Mark that you want to use stdin and raise an exception if it's already been used.
    def can_i_haz_stdin!
      raise ArgumentError, "stdin (-) cannot be specified multiple times" if @stdin_used
      @stdin_used = true
    end

    # @param parent data structure to recurse over
    # @param key to access
    # @yield context of key and parent
    # @yieldparam parent the parent object
    # @yieldparam key the last child node
    def access_key(parent, key, write: false)
      splits = key.split(".")
      last_key = splits.length - 1
      splits.each_with_index do |curr, idx|
        if parent.is_a?(Array)
          k = curr.to_i
          raise ArgumentError, "Array index must be a positive number" if curr != k.to_s || k < 0
        elsif parent.respond_to?(:[])
          k = curr
        else
          raise ArgumentError, "No such key: #{key.inspect}"
        end

        return yield(parent, k) if idx == last_key

        if parent[k].nil?
          return nil unless write
          parent[k] = {}
        end
        parent = parent[k]
      end
    end
  end

  class Encrypt < Base
    def action_name
      "encrypt"
    end

    def parse_additional_options(opts)
      opts.separator("\nEncrypt options:")

      @new_secret_key = nil
      opts.on("--new-secret-key=NEW_SECRET", String, *split(<<~DOC)) do |value|
        Encryption key used to encrypt strings in the file on output.
        This option can be used to change the encryption key. If set to '-', read from STDIN.
      DOC
        @new_secret_key = get_secret_key(value)
      end

      @in_place = false
      opts.on("--in-place", "Update the input file instead of writing to stdout.") do |value|
        @in_place = true
      end
    end

    def run!
      if @new_secret_key && !@new_secret_key.empty?
        secrets.encryption_key = @new_secret_key
      end

      if @in_place
        raise ArgumentError, "Cannot perform in place editing on streams" unless @input.is_a?(String)
        # make sure we read the file **before** writing to it.
        contents = encrypted_file_contents
        File.open(@input, "w") do |file|
          file.write(contents)
        end
      else
        $stdout.write(encrypted_file_contents)
        $stdout.flush
      end
    end
  end

  class Decrypt < Base
    def action_name
      "decrypt"
    end

    def run!
      decrypted = secrets.to_h
      string = (format == :yaml ? YAML.dump(decrypted) : JSON.pretty_generate(decrypted))
      string << $/ unless string.end_with?($/) # ensure file ends with system dependent new line
      $stdout.write(string)
      $stdout.flush
    end
  end

  class Read < Base
    attr_reader :key

    def action_name
      "read"
    end

    def parse_additional_options(opts)
      opts.separator("\n Read options:")
      @key = nil
      opts.on("-k", "--key KEY", String, "Key from the file to output. You can use dot notation to read a nested key.") do |value|
        @key = value
      end
    end

    def run!
      raise ArgumentError.new("key is required") if @key.nil? || @key.empty?
      val = secrets.to_h
      val = access_key(val, @key) { |parent, key| parent[key] }
      $stdout.write(val)
      $stdout.flush
    end
  end

  class Edit < Encrypt
    attr_reader :actions

    def action_name
      "edit"
    end

    def parse_additional_options(opts)
      opts.separator("\nEdit options:")

      @actions = []
      set_encrypted_docs = split(<<~HELP)
        Set an encrypted value in the file. You can use dot notation to set a nested value.
        If no VALUE is specified, the key will be moved to the encrypted keys while keeping any existing value.
      HELP
      opts.on("-e", "--set-encrypted KEY[=VALUE]", String, *set_encrypted_docs) do |value|
        key, val = value.split("=", 2)
        @actions << [:encrypt, key, val]
      end

      set_decrypted_docs = split(<<~HELP)
        Set a plain text value in the file. You can use dot notation to set a nested value. If no VALUE is specified,
        the key will be moved to the plain text keys while keeping any existing value.
      HELP
      opts.on("-d", "--set-decrypted KEY[=VALUE]", String, *set_decrypted_docs) do |value|
        key, val = value.split("=", 2)
        @actions << [:decrypt, key, val]
      end

      opts.on("-r", "--remove KEY", String, "Remove a key from the file. You can use dot notation to remove a nested value.") do |value|
        @actions << [:remove, value, nil]
      end

      super
    end

    def run!
      @actions.each do |action, key, value|
        raise ArgumentError.new("cannot set a key beginning with dot") if key.start_with?(".")
        case action
        when :encrypt
          secrets.encrypt!(key.split(".").first)
          unless value.nil?
            access_key(secrets, key, write: true) do |parent, child|
              parent[child] = value
            end
          end
        when :decrypt
          secrets.decrypt!(key.split(".").first)
          unless value.nil?
            access_key(secrets, key, write: true) do |parent, child|
              parent[child] = value
            end
          end
        when :remove
          access_key(secrets, key) do |parent, child|
            if parent.is_a?(Array)
              parent.delete_at(child)
            else
              parent.delete(child)
            end
          end
        end
      end

      super
    end
  end
end
