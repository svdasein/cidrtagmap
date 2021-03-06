Gem::Specification.new do |s|
  s.name = 'logstash-filter-cidrtagmap'
  s.version         = '2.2.1'
  s.licenses = ['Apache-2.0']
  s.summary = "Filter adds tags to events in logstash based on a table of cidr->name mappings  and optionally adds asn name fields"
  s.description     = "This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program.  Filter adds tags to events in logstash based on a table of cidr->name mappings  and optionally adds asn name fields"
  s.authors = ["svdasein"]
  s.email = 'daveparker01@gmail.com'
  s.homepage = "https://github.com/svdasein/cidrtagmap"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency 'logstash-devutils'

  s.add_runtime_dependency "redis","~> 3.0"
end
