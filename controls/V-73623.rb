control "V-73623" do
  title "The built-in administrator account must be renamed."
  desc  "The built-in administrator account is a well-known account subject to
  attack. Renaming this account to an unidentified name improves the protection
  of this account and the system."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73623"
  tag "rid": "SV-88287r1_rule"
  tag "stig_id": "WN16-SO-000030"
  tag "fix_id": "F-80073r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> Security Options.

  If the value for \"Accounts: Rename administrator account\" is not set to a
  value other than \"Administrator\", this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  \"Accounts: Rename administrator account\" to a name other than
  \"Administrator\"."
  describe user('Administrator') do
    it { should_not exist }
  end
end

