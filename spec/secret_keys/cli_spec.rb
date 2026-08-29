# frozen_string_literal: true

require "spec_helper"
require_relative "../../lib/secret_keys/cli"

require "tmpdir"
require "shellwords"
require "rbconfig"
require "open3"

RSpec.describe SecretKeys::CLI do
  let(:decrypted_file_path) { File.join(__dir__, "..", "fixtures", "decrypted.json") }
  let(:encrypted_file_path) { File.join(__dir__, "..", "fixtures", "encrypted.json") }
  let(:secret_key_path) { File.join(__dir__, "..", "fixtures", "secret_key") }
  let(:stdout) { StringIO.new }

  around :each do |example|
    $stdin = StringIO.new("{}")
    $stdout = stdout
    example.call
  ensure
    $stdin = STDIN
    $stdout = STDOUT
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
        command = SecretKeys::CLI::Base.new(["--secret-key", "-", decrypted_file_path])
        expect(command.secret_key).to eq "foobar"
      end

      it "should read the secret key from the --secret-key-file option" do
        command = SecretKeys::CLI::Base.new(["--secret-key-file", secret_key_path])
        expect(command.secret_key).to eq "SECRET_KEY"
      end

      it "should raise an ArgumentError if the secret key file does not exist" do
        expect { SecretKeys::CLI::Base.new(["--secret-key-file", "/no/such/file"]) }.to raise_error(ArgumentError, /does not exist/)
      end

      it "should not allow using stdin for file and secret key" do
        expect { SecretKeys::CLI::Base.new(["--secret-key", "-", "-"]) }.to raise_error(ArgumentError, /stdin/)
      end

      it "should not allow using both --secret-key and --secret-key-file" do
        expect { SecretKeys::CLI::Base.new(["--secret-key", "-", "-"]) }.to raise_error(ArgumentError, /stdin/)
      end
    end

    describe "output format option" do
      it "should json as default" do
        command = SecretKeys::CLI::Base.new(["-s TEST"])
        expect(command.format).to eq :json
      end

      it "should set the output format from the --format option" do
        command = SecretKeys::CLI::Base.new(["--format", "yaml"])
        expect(command.format).to eq :yaml
      end

      it "should uset the default format from secrets input format if not specified" do
        command = SecretKeys::CLI::Base.new(["-s TEST"])
        expect(command.secrets).to receive(:input_format).and_return(:yaml)
        expect(command.format).to eq :yaml
      end
    end

    describe "input and output" do
      it "should default to using $stdin and $stdout" do
        command = SecretKeys::CLI::Base.new([])
        expect(command.input).to eq $stdin
      end

      it "should use $stdin if set to -" do
        command = SecretKeys::CLI::Base.new(["-"])
        expect(command.input).to eq $stdin
      end

      it "should set the input with a file path" do
        command = SecretKeys::CLI::Base.new([decrypted_file_path])
        expect(command.input).to eq decrypted_file_path
      end
    end
  end

  describe SecretKeys::CLI::Init do
    it "should initialize a new file readable only by the owner" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "secrets.json")
        command = SecretKeys::CLI::Init.new(["--secret-key=SECRET_KEY", path])
        command.run!
        secrets = SecretKeys.new(path, "SECRET_KEY")
        expect(secrets.to_h).to eq({})
        expect(File.stat(path).mode & 0o7777).to eq 0o600
      end
    end

    it "should refuse to overwrite an existing file" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "secrets.json")
        File.write(path, "original contents")
        command = SecretKeys::CLI::Init.new(["--secret-key=SECRET_KEY", path])
        original_stderr = $stderr
        $stderr = StringIO.new
        begin
          expect { command.run! }.to raise_error(SystemExit)
        ensure
          $stderr = original_stderr
        end
        expect(File.read(path)).to eq "original contents"
      end
    end
  end

  describe SecretKeys::CLI::Encrypt do
    it "should encrypt the input file" do
      command = SecretKeys::CLI::Encrypt.new(["--secret-key=SECRET_KEY", encrypted_file_path])
      command.run!
      stdout.rewind
      secrets = SecretKeys.new(stdout, "SECRET_KEY")
      raw_json = JSON.parse(stdout.string)
      expect(secrets["plaintext"]).to eq "not encrypted"
      expect(raw_json[SecretKeys::ENCRYPTED]).to include("plaintext")
      expect(raw_json[SecretKeys::ENCRYPTED]["plaintext"]).to_not eq secrets["plaintext"]
    end

    it "should encrypt the input file in place if the --in-place option is set" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        temp_file.write(File.read(encrypted_file_path))
        temp_file.rewind
        command = SecretKeys::CLI::Encrypt.new(["--secret-key=SECRET_KEY", "--in-place", temp_file.path])
        command.run!
        secrets = SecretKeys.new(temp_file.path, "SECRET_KEY")
        # Read by path since the in-place write atomically replaces the file.
        raw_json = JSON.parse(File.read(temp_file.path))
        expect(secrets["plaintext"]).to eq "not encrypted"
        expect(raw_json[SecretKeys::ENCRYPTED]).to include("plaintext")
        expect(raw_json[SecretKeys::ENCRYPTED]["plaintext"]).to_not eq secrets["plaintext"]
      ensure
        temp_file.unlink
      end
    end

    it "should raise on error on --in-place when passed stdin" do
      command = SecretKeys::CLI::Encrypt.new(["--secret-key=SECRET_KEY", "--in-place", "-"])
      expect { command.run! }.to raise_error(ArgumentError)
    end

    it "should encrypt the input file using a new encryption key" do
      command = SecretKeys::CLI::Encrypt.new(["--secret-key=SECRET_KEY", "--new-secret-key=NEW_SECRET", encrypted_file_path])
      command.run!
      stdout.rewind
      secrets = SecretKeys.new(stdout, "NEW_SECRET")
      expect(secrets["foo"]).to eq "bar"
    end
  end

  describe SecretKeys::CLI::Decrypt do
    it "should decrypt the input file" do
      command = SecretKeys::CLI::Decrypt.new(["--secret-key=SECRET_KEY", encrypted_file_path])
      command.run!
      json = JSON.parse(stdout.string)
      expect(json).to eq JSON.parse(File.read(decrypted_file_path))
    end
  end

  describe SecretKeys::CLI::Read do
    it "should read a key from the input file" do
      command = SecretKeys::CLI::Read.new(["--secret-key=SECRET_KEY", "--key=foo", encrypted_file_path])
      command.run!
      value = stdout.string
      expect(value).to eq "bar"
    end

    it "should read a nested key from the input file" do
      command = SecretKeys::CLI::Read.new(["--secret-key=SECRET_KEY", "--key=complex.one", encrypted_file_path])
      command.run!
      value = stdout.string
      expect(value).to eq "value_1"
    end

    it "should not output anything if the key does not exist" do
      command = SecretKeys::CLI::Read.new(["--secret-key=SECRET_KEY", "--key=complex.nothing", encrypted_file_path])
      command.run!
      value = stdout.string
      expect(value).to eq ""
    end
  end

  describe SecretKeys::CLI::Edit do
    it "should add a key to the encrypted keys" do
      command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--set-encrypted", "new=thing", encrypted_file_path])
      command.run!
      stdout.rewind
      secrets = SecretKeys.new(stdout, "SECRET_KEY")
      expect(secrets["new"]).to eq "thing"
      expect(secrets.encrypted?("new")).to eq true
    end

    it "should move a key to the encrypted keys if it exists and no value was specified" do
      command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--set-encrypted", "not_encrypted", encrypted_file_path])
      command.run!
      stdout.rewind
      secrets = SecretKeys.new(stdout, "SECRET_KEY")
      expect(secrets["not_encrypted"]).to eq "plain text value"
      expect(secrets.encrypted?("not_encrypted")).to eq true
    end

    it "should add a nested key to the encrypted keys" do
      command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--set-encrypted", "complex.four=four", encrypted_file_path])
      command.run!
      stdout.rewind
      secrets = SecretKeys.new(stdout, "SECRET_KEY")
      expect(secrets["complex"]["four"]).to eq "four"
      expect(secrets.encrypted?("complex")).to eq true
    end

    it "should add a key to the plain text keys" do
      command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--set-decrypted", "new=thing", encrypted_file_path])
      command.run!
      stdout.rewind
      secrets = SecretKeys.new(stdout, "SECRET_KEY")
      expect(secrets["new"]).to eq "thing"
      expect(secrets.encrypted?("new")).to eq false
    end

    it "should move a key to the plain text keys if it exists and no value was specified" do
      command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--set-decrypted", "foo", encrypted_file_path])
      command.run!
      stdout.rewind
      secrets = SecretKeys.new(stdout, "SECRET_KEY")
      expect(secrets["foo"]).to eq "bar"
      expect(secrets.encrypted?("foo")).to eq false
    end

    it "should add a nested key to the plain text keys" do
      command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--set-decrypted", "thing.part=woot", encrypted_file_path])
      command.run!
      stdout.rewind
      secrets = SecretKeys.new(stdout, "SECRET_KEY")
      expect(secrets["thing"]["part"]).to eq "woot"
      expect(secrets.encrypted?("thing")).to eq false
    end

    it "should remove a key from the encrypted keys" do
      command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--remove", "not_encrypted", encrypted_file_path])
      command.run!
      stdout.rewind
      secrets = SecretKeys.new(stdout, "SECRET_KEY")
      expect(secrets).to_not include("not_encrypted")
    end

    it "should remove a key from the plain text keys" do
      command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--remove", "foo", encrypted_file_path])
      command.run!
      stdout.rewind
      secrets = SecretKeys.new(stdout, "SECRET_KEY")
      expect(secrets).to_not include("foo")
    end

    it "should encrypt the input file in place if the --in-place option is set" do
      temp_file = Tempfile.new("secret_keys_cli_test")
      begin
        temp_file.write(File.read(encrypted_file_path))
        temp_file.rewind
        command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--in-place", temp_file.path])
        command.run!
        secrets = SecretKeys.new(temp_file.path, "SECRET_KEY")
        # Read by path since the in-place write atomically replaces the file.
        raw_json = JSON.parse(File.read(temp_file.path))
        expect(secrets["plaintext"]).to eq "not encrypted"
        expect(raw_json[SecretKeys::ENCRYPTED]).to include("plaintext")
        expect(raw_json[SecretKeys::ENCRYPTED]["plaintext"]).to_not eq secrets["plaintext"]
      ensure
        temp_file.unlink
      end
    end

    it "should encrypt the input file using a new encryption key" do
      command = SecretKeys::CLI::Edit.new(["--secret-key=SECRET_KEY", "--new-secret-key=NEW_SECRET", encrypted_file_path])
      command.run!
      stdout.rewind
      secrets = SecretKeys.new(stdout, "NEW_SECRET")
      expect(secrets["foo"]).to eq "bar"
    end
  end

  describe SecretKeys::CLI::Open do
    let(:fake_editor) { File.expand_path("../fixtures/fake_editor.rb", __dir__) }

    # The editor is a child process; keep the spec run's bundler environment out of it.
    around(:each) { |example| without_bundler_env { example.run } }

    # Build an $EDITOR command line that runs the fake editor in the given mode. The fake editor
    # records the temporary file it was handed in record_path.
    def editor_command(mode, record_path)
      [RbConfig.ruby, fake_editor, mode, record_path].shelljoin
    end

    def editor_record(record_path)
      JSON.parse(File.read(record_path))
    end

    # Copy the encrypted fixture into a temp dir and yield its path along with a record path.
    def with_secrets_file(extension: ".json")
      Dir.mktmpdir do |dir|
        path = File.join(dir, "secrets#{extension}")
        contents = File.read(encrypted_file_path)
        contents = YAML.dump(JSON.parse(contents)) if extension != ".json"
        File.write(path, contents)
        yield path, File.join(dir, "record.json")
      end
    end

    it "should save the edits made in the editor while keeping the ciphertext of unchanged values" do
      with_secrets_file do |path, record_path|
        original_json = JSON.parse(File.read(path))
        with_environment(VISUAL: nil, EDITOR: editor_command("edit", record_path)) do
          SecretKeys::CLI::Open.new(["--secret-key=SECRET_KEY", path]).run!
        end

        secrets = SecretKeys.new(path, "SECRET_KEY")
        expect(secrets["foo"]).to eq "edited"
        expect(secrets["new_secret"]).to eq "shh"
        expect(secrets.encrypted?("new_secret")).to eq true
        expect(secrets["plaintext"]).to eq "not encrypted"
        expect(secrets.encrypted?("plaintext")).to eq false
        expect(secrets["not_encrypted"]).to eq "plain text value"
        expect(secrets.encrypted?("not_encrypted")).to eq true
        expect(secrets["array"]).to eq ["a", "b", "c"]

        new_json = JSON.parse(File.read(path))
        expect(new_json[SecretKeys::ENCRYPTED]["array"]).to eq original_json[SecretKeys::ENCRYPTED]["array"]
        expect(new_json[SecretKeys::ENCRYPTED]["complex"]).to eq original_json[SecretKeys::ENCRYPTED]["complex"]
        expect(new_json[SecretKeys::ENCRYPTED]["foo"]).to_not eq original_json[SecretKeys::ENCRYPTED]["foo"]
        expect(stdout.string).to eq ""
      end
    end

    it "should give the editor a private temporary file and remove it afterwards" do
      with_secrets_file do |path, record_path|
        with_environment(VISUAL: nil, EDITOR: editor_command("noop", record_path)) do
          SecretKeys::CLI::Open.new(["--secret-key=SECRET_KEY", path]).run!
        end
        record = editor_record(record_path)
        expect(record["path"]).to end_with("/secrets.json")
        expect(record["path"]).to_not eq path
        expect(record["file_mode"]).to eq "600"
        expect(record["dir_mode"]).to eq "700"
        expect(File.exist?(record["path"])).to eq false
        expect(File.exist?(File.dirname(record["path"]))).to eq false
      end
    end

    it "should write the decrypted values to the temporary file" do
      with_secrets_file do |path, record_path|
        # The fake editor fails after recording, so the temp file is never saved back.
        capture_path = File.join(File.dirname(path), "capture.json")
        editor = [RbConfig.ruby, "-e", "File.write(ARGV[0], File.read(ARGV[1]))", capture_path].shelljoin
        with_environment(VISUAL: nil, EDITOR: editor) do
          SecretKeys::CLI::Open.new(["--secret-key=SECRET_KEY", path]).run!
        end
        decrypted = JSON.parse(File.read(capture_path))
        expect(decrypted["not_encrypted"]).to eq "plain text value"
        expect(decrypted[SecretKeys::ENCRYPTED]["foo"]).to eq "bar"
        expect(decrypted[SecretKeys::ENCRYPTED]["complex"]["more"]).to eq [{"three" => "value_3"}]
        expect(decrypted[SecretKeys::ENCRYPTED].keys).to_not include(".salt", ".key", ".version")
      end
    end

    it "should leave the file untouched if nothing was changed in the editor" do
      with_secrets_file do |path, record_path|
        original_contents = File.read(path)
        with_environment(VISUAL: nil, EDITOR: editor_command("noop", record_path)) do
          SecretKeys::CLI::Open.new(["--secret-key=SECRET_KEY", path]).run!
        end
        expect(File.read(path)).to eq original_contents
      end
    end

    it "should fail without saving if the editor exits with an error" do
      with_secrets_file do |path, record_path|
        original_contents = File.read(path)
        with_environment(VISUAL: nil, EDITOR: editor_command("fail", record_path)) do
          command = SecretKeys::CLI::Open.new(["--secret-key=SECRET_KEY", path])
          expect { command.run! }.to raise_error(ArgumentError, /exited with status 3/)
        end
        expect(File.read(path)).to eq original_contents
        expect(File.exist?(editor_record(record_path)["path"])).to eq false
      end
    end

    it "should fail without saving if the edited file cannot be parsed" do
      with_secrets_file do |path, record_path|
        original_contents = File.read(path)
        with_environment(VISUAL: nil, EDITOR: editor_command("invalid", record_path)) do
          command = SecretKeys::CLI::Open.new(["--secret-key=SECRET_KEY", path])
          expect { command.run! }.to raise_error(ArgumentError, /could not be loaded/)
        end
        expect(File.read(path)).to eq original_contents
      end
    end

    it "should prefer $VISUAL over $EDITOR" do
      with_secrets_file do |path, record_path|
        with_environment(VISUAL: editor_command("noop", record_path), EDITOR: "/no/such/editor") do
          SecretKeys::CLI::Open.new(["--secret-key=SECRET_KEY", path]).run!
        end
        expect(File.exist?(record_path)).to eq true
      end
    end

    it "should edit YAML files as YAML" do
      with_secrets_file(extension: ".yml") do |path, record_path|
        with_environment(VISUAL: nil, EDITOR: editor_command("edit", record_path)) do
          SecretKeys::CLI::Open.new(["--secret-key=SECRET_KEY", path]).run!
        end
        expect(editor_record(record_path)["path"]).to end_with("/secrets.yml")
        expect { JSON.parse(File.read(path)) }.to raise_error(JSON::ParserError)
        secrets = SecretKeys.new(path, "SECRET_KEY")
        expect(secrets.input_format).to eq :yaml
        expect(secrets["foo"]).to eq "edited"
        expect(secrets.encrypted?("new_secret")).to eq true
      end
    end

    it "should not open a stream in an editor" do
      command = SecretKeys::CLI::Open.new(["--secret-key=SECRET_KEY", "-"])
      expect { command.run! }.to raise_error(ArgumentError, /file path/)
    end
  end

  describe SecretKeys::CLI::Exec do
    # The command is a child process; keep the spec run's bundler environment out of it.
    around(:each) { |example| without_bundler_env { example.run } }

    def exec_command(*args)
      SecretKeys::CLI::Exec.new(["--secret-key=SECRET_KEY", *args])
    end

    describe "#environment" do
      it "should map string values to upcased variable names, joining nested keys with underscores" do
        env = exec_command(encrypted_file_path, "--", "true").environment
        expect(env).to eq({
          "FOO" => "bar",
          "ARRAY_0" => "a",
          "ARRAY_1" => "b",
          "ARRAY_2" => "c",
          "COMPLEX_ONE" => "value_1",
          "COMPLEX_TWO" => "value_2",
          "COMPLEX_MORE_0_THREE" => "value_3",
          "PLAINTEXT" => "not encrypted",
          "NOT_ENCRYPTED" => "plain text value"
        })
      end

      it "should not export values that are not strings" do
        env = exec_command(encrypted_file_path, "--", "true").environment
        expect(env).to_not include("COUNT")
      end

      it "should prepend the --prefix to generated names" do
        env = exec_command("--prefix", "app_", encrypted_file_path, "--", "true").environment
        expect(env["APP_FOO"]).to eq "bar"
        expect(env["APP_COMPLEX_ONE"]).to eq "value_1"
        expect(env).to_not include("FOO")
      end

      it "should replace characters that are not valid in variable names" do
        Dir.mktmpdir do |dir|
          path = File.join(dir, "secrets.json")
          File.write(path, JSON.dump({"api-key" => "k", "1st" => "one", "a b" => {"c" => "x"}}))
          env = exec_command(path, "--", "true").environment
          expect(env).to eq({"API_KEY" => "k", "_1ST" => "one", "A_B_C" => "x"})
        end
      end

      it "should use the name given with --key for that path" do
        env = exec_command("--key", "complex.one=DB_PASSWORD", "-k", "foo=FOO_BAR", encrypted_file_path, "--", "true").environment
        expect(env["DB_PASSWORD"]).to eq "value_1"
        expect(env["FOO_BAR"]).to eq "bar"
        expect(env).to_not include("COMPLEX_ONE", "FOO")
      end

      it "should not apply the prefix to names given with --key" do
        env = exec_command("--prefix", "APP_", "--key", "foo=FOO", encrypted_file_path, "--", "true").environment
        expect(env["FOO"]).to eq "bar"
        expect(env["APP_COMPLEX_ONE"]).to eq "value_1"
      end

      it "should raise an error if a --key path has no string value" do
        expect { exec_command("--key", "nothing=X", encrypted_file_path, "--", "true").environment }.to raise_error(ArgumentError, /nothing/)
        expect { exec_command("--key", "count=X", encrypted_file_path, "--", "true").environment }.to raise_error(ArgumentError, /count/)
        expect { exec_command("--key", "complex=X", encrypted_file_path, "--", "true").environment }.to raise_error(ArgumentError, /complex/)
      end

      it "should raise an error if a --key name is not a valid variable name" do
        expect { exec_command("--key", "foo=BAD-NAME", encrypted_file_path, "--", "true").environment }.to raise_error(ArgumentError, /BAD-NAME/)
      end

      it "should raise an error if two keys map to the same variable name" do
        expect { exec_command("--key", "foo=PLAINTEXT", encrypted_file_path, "--", "true").environment }.to raise_error(ArgumentError, /PLAINTEXT/)
      end

      it "should raise an error if --key is missing a name" do
        expect { exec_command("--key", "foo", encrypted_file_path, "--", "true") }.to raise_error(ArgumentError, /PATH=NAME/)
      end
    end

    describe "command parsing" do
      it "should take the command after --" do
        command = exec_command(encrypted_file_path, "--", "printenv", "-0", "FOO")
        expect(command.input).to eq encrypted_file_path
        expect(command.command).to eq ["printenv", "-0", "FOO"]
      end

      it "should take the command without --" do
        command = exec_command(encrypted_file_path, "printenv", "FOO")
        expect(command.command).to eq ["printenv", "FOO"]
      end

      it "should raise an error if no command is given" do
        expect { exec_command(encrypted_file_path).run! }.to raise_error(ArgumentError, /No command/)
      end

      it "should raise an error if the input is a stream" do
        expect { exec_command("-", "--", "true").run! }.to raise_error(ArgumentError, /file path/)
      end
    end

    describe "#run!" do
      it "should replace the process with the command and the variables in its environment" do
        command = exec_command("--prefix", "APP_", encrypted_file_path, "--", "printenv", "APP_FOO")
        expect(Kernel).to receive(:exec).with(hash_including("APP_FOO" => "bar", "APP_COMPLEX_ONE" => "value_1"), "printenv", "APP_FOO")
        command.run!
        expect(stdout.string).to eq ""
      end

      it "should exit with status 127 if the command is not found" do
        command = exec_command(encrypted_file_path, "--", "no_such_command_xyz")
        allow(Kernel).to receive(:exec).and_raise(Errno::ENOENT)
        original_stderr = $stderr
        $stderr = StringIO.new
        begin
          expect { command.run! }.to raise_error(SystemExit) { |error| expect(error.status).to eq 127 }
          expect($stderr.string).to include("no_such_command_xyz")
        ensure
          $stderr = original_stderr
        end
      end

      it "should run the command with the decrypted values in its environment" do
        executable = File.expand_path("../../bin/secret_keys", __dir__)
        child = [RbConfig.ruby, "-e", "print ENV['APP_FOO'], '|', ENV['APP_COMPLEX_MORE_0_THREE'], '|', ENV.fetch('APP_COUNT', 'unset')"]
        out, err, status = Open3.capture3(RbConfig.ruby, executable, "exec", "--secret-key=SECRET_KEY", "--prefix", "APP_", encrypted_file_path, "--", *child, stdin_data: "")
        expect(err).to eq ""
        expect(status.exitstatus).to eq 0
        expect(out).to eq "bar|value_3|unset"
      end
    end
  end
end
