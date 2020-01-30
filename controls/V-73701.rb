control 'V-73701' do
  title "Windows Server 2016 must be configured to use FIPS-compliant
  algorithms for encryption, hashing, and signing."
  desc "This setting ensures the system uses algorithms that are
  FIPS-compliant for encryption, hashing, and signing. FIPS-compliant algorithms
  meet specific standards established by the U.S. Government and must be the
  algorithms used for all OS encryption functions.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000033-GPOS-00014'
  tag "satisfies": ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000478-GPOS-00223']
  tag "gid": 'V-73701'
  tag "rid": 'SV-88365r1_rule'
  tag "stig_id": 'WN16-SO-000430'
  tag "fix_id": 'F-80151r1_fix'
  tag "cci": ['CCI-000068', 'CCI-002450']
  tag "nist": ['AC-17 (2)', 'SC-13', 'Rev_4']
  tag "documentable": false
  desc "check", "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy\\

  Value Name: Enabled

  Value Type: REG_DWORD
  Value: 0x00000001 (1)

  Clients with this setting enabled will not be able to communicate via digitally
  encrypted or signed protocols with servers that do not support these
  algorithms. Both the browser and web server must be configured to use TLS;
  otherwise. the browser will not be able to connect to a secure site."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >> System
  cryptography: Use FIPS compliant algorithms for encryption, hashing, and
  signing to Enabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy') do
    it { should have_property 'Enabled' }
    its('Enabled') { should cmp 1 }
  end
end
