control 'V-73625' do
  title 'The built-in guest account must be renamed.'
  desc  "The built-in guest account is a well-known user account on all Windows
  systems and, as initially installed, does not require a password. This can
  allow access to system resources by unauthorized users. Renaming this account
  to an unidentified name improves the protection of this account and the system."
  impact 0.5
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-73625'
  tag "rid": 'SV-88289r1_rule'
  tag "stig_id": 'WN16-SO-000040'
  tag "fix_id": 'F-80075r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> Security Options.

  If the value for \"Accounts: Rename guest account\" is not set to a value other
  than \"Guest\", this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  \"Accounts: Rename guest account\" to a name other than \"Guest\"."
  describe user('Guest') do
    it { should_not exist }
  end
end
