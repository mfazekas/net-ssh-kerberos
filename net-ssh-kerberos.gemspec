# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{net-ssh-kerberos}
  s.version = "0.1.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Joe Khoobyar"]
  s.date = %q{2009-10-13}
  s.description = %q{Adds support for Microsoft Kerberos (SSPI) with the Net:SSH gem.
}
  s.email = %q{joe@ankhcraft.com}
  s.extra_rdoc_files = [
    "LICENSE",
    "README.rdoc"
  ]
  s.files = [
    "LICENSE",
    "README.rdoc",
    "Rakefile",
    "VERSION.yml",
    "lib/net/ssh/authentication/methods/gssapi_with_mic.rb",
    "lib/net/ssh/kerberos.rb",
    "lib/net/ssh/kerberos/constants.rb",
    "lib/net/ssh/kerberos/gss.rb",
    "lib/net/ssh/kerberos/gss/api.rb",
    "lib/net/ssh/kerberos/gss/context.rb",
    "lib/net/ssh/kerberos/kex.rb",
    "lib/net/ssh/kerberos/kex/krb5_diffie_hellman_group1_sha1.rb",
    "lib/net/ssh/kerberos/kex/krb5_diffie_hellman_group_exchange_sha1.rb",
    "lib/net/ssh/kerberos/sspi.rb",
    "lib/net/ssh/kerberos/sspi/api.rb",
    "lib/net/ssh/kerberos/sspi/context.rb",
    "test/net_ssh_kerberos_test.rb",
    "test/sspi_context_test.rb",
    "test/sspi_test.rb",
    "test/test_helper.rb"
  ]
  s.homepage = %q{http://github.com/joekhoobyar/net-ssh-kerberos}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{net-ssh-krb}
  s.rubygems_version = %q{1.3.4}
  s.summary = %q{Add Kerberos support to Net::SSH}
  s.test_files = [
    "test/net_ssh_kerberos_test.rb",
    "test/sspi_context_test.rb",
    "test/sspi_test.rb",
    "test/test_helper.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<net-ssh>, [">= 2.0"])
      s.add_runtime_dependency(%q<rubysspi>, [">= 1.3"])
    else
      s.add_dependency(%q<net-ssh>, [">= 2.0"])
      s.add_dependency(%q<rubysspi>, [">= 1.3"])
    end
  else
    s.add_dependency(%q<net-ssh>, [">= 2.0"])
    s.add_dependency(%q<rubysspi>, [">= 1.3"])
  end
end
