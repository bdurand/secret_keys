begin
  require "bundler/setup"
rescue LoadError
  puts "You must `gem install bundler` and `bundle install` to run rake tasks"
end

require "yard"
YARD::Rake::YardocTask.new(:yard)

require "bundler/gem_tasks"

task :release do
  unless `git rev-parse --abbrev-ref HEAD`.chomp == "main"
    warn "Gem can only be released from the main branch"
    exit 1
  end
end

require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

task default: :spec

require "standard/rake"

task :console do
  require File.join(__dir__, "lib/secret_keys")
  require "irb"

  ARGV.clear
  IRB.start
end
