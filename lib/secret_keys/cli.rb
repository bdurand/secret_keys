# frozen_string_literal: true

require "optparse"
require "io/console"
require "shellwords"
require "stringio"
require "tmpdir"

require_relative "../secret_keys"

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

    # Subclasses can override this method to consume any arguments left after the input file.
    # By default no extra arguments are allowed.
    def parse_additional_arguments(argv)
      raise ArgumentError.new("Too many arguments") unless argv.empty?
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
      serialize(secrets.encrypted_hash)
    end

    # Serialize a hash in the output format with a trailing newline.
    def serialize(hash)
      string = ((format == :yaml) ? YAML.dump(hash) : JSON.pretty_generate(hash))
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
          raise ArgumentError, "Secret key file '#{value}' does not exist" unless File.exist?(value)
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

      parse_additional_arguments(argv)
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
        elsif parent.is_a?(Hash) || parent.is_a?(SecretKeys)
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

  class Init < Base
    def action_name
      "init"
    end

    def run!
      @secrets = SecretKeys.new({}, secret_key)
      if input.is_a?(String)
        contents = encrypted_file_contents
        begin
          # Open with exclusive create so a file created by another process
          # between now and the write can never be clobbered. The file is
          # created readable and writable only by the owner.
          File.open(input, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
            file.write(contents)
          end
        rescue Errno::EEXIST
          warn "Error: Cannot init preexisting file '#{input}'"
          warn "You may want to try calling `secret_keys encrypt/edit` instead"
          exit 1
        end
      else
        $stdout.write(encrypted_file_contents)
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
      opts.on("-i", "--in-place", "Update the input file instead of writing to stdout.") do |value|
        @in_place = true
      end

      @encrypt_all = false
      opts.on("--encrypt-all", "Encrypt all keys in the file") do |value|
        @encrypt_all = value
      end
    end

    def run!
      if @new_secret_key && !@new_secret_key.empty?
        secrets.encryption_key = @new_secret_key
      end

      if @encrypt_all
        secrets.each_key do |key|
          secrets.encrypt!(key)
        end
      end

      if @in_place
        raise ArgumentError, "Cannot perform in place editing on streams" unless @input.is_a?(String)
        # make sure we read the file **before** writing to it.
        contents = encrypted_file_contents
        SecretKeys.atomic_write(@input, contents)
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
      $stdout.write(serialize(secrets.to_h))
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

  # Open the decrypted file in an editor and re-encrypt it when the editor exits. Values that
  # were not changed in the editor keep their existing ciphertext.
  class Open < Base
    DEFAULT_EDITOR = "vi"

    def action_name
      "open"
    end

    def run!
      raise ArgumentError, "Cannot open a stream in an editor; specify a file path" unless input.is_a?(String)

      original = decrypted_file_contents
      edited = edit_in_editor(original)
      # Leave the file untouched if nothing was changed in the editor.
      return if edited == original

      apply_edits(edited)
      secrets.save(input, format: format)
    end

    private

    # The decrypted document in the same shape as the encrypted file: plain text keys at the
    # top level and secret keys under ".encrypted", without the internal salt/key/version entries.
    def decrypted_file_contents
      plain = {}
      encrypted = {}
      secrets.to_h.each do |key, value|
        if secrets.encrypted?(key)
          encrypted[key] = value
        else
          plain[key] = value
        end
      end
      plain[SecretKeys::ENCRYPTED] = encrypted
      serialize(plain)
    end

    # Write the contents to a file only the current user can read inside a private temporary
    # directory, run the editor on it, and return the edited contents. The block form of
    # Dir.mktmpdir removes the directory and everything in it (including any swap or backup
    # files the editor created) in an ensure block, so the plain text never outlives this call.
    def edit_in_editor(contents)
      Dir.mktmpdir("secret_keys") do |dir|
        path = File.join(dir, temp_file_name)
        File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
          file.write(contents)
        end
        run_editor(path)
        File.read(path)
      end
    end

    # Run $VISUAL or $EDITOR (which may include arguments) on the path.
    def run_editor(path)
      editor = [ENV["VISUAL"], ENV["EDITOR"]].find { |value| value && !value.empty? } || DEFAULT_EDITOR
      command = Shellwords.split(editor)
      raise ArgumentError, "No editor configured; set the VISUAL or EDITOR environment variable" if command.empty?

      unless system(*command, path)
        raise ArgumentError, "Editor #{editor.inspect} exited with status #{$?.exitstatus}; no changes were saved"
      end
    end

    # Name the temporary file after the input file so the editor picks the right syntax highlighting.
    def temp_file_name
      extension = ((format == :yaml) ? ".yml" : ".json")
      "#{File.basename(input, ".*")}#{extension}"
    end

    # Replace the values and the list of encrypted keys with the edited document. The original
    # ciphertexts are kept for values that did not change.
    def apply_edits(contents)
      edited = begin
        SecretKeys.new(StringIO.new(contents), secret_key)
      rescue => e
        raise ArgumentError, "Edited file could not be loaded (#{e.message}); no changes were saved"
      end

      secrets.keys.each { |key| secrets.decrypt!(key) }
      secrets.clear
      secrets.merge!(edited.to_h)
      edited.each_key { |key| secrets.encrypt!(key) if edited.encrypted?(key) }
    end
  end
end
