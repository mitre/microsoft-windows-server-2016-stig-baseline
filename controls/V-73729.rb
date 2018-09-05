control "V-73729" do
  title "The Access Credential Manager as a trusted caller user right must not
  be assigned to any groups or accounts."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    Accounts with the \"Access Credential Manager as a trusted caller\" user
  right may be able to retrieve the credentials of other accounts from Credential
  Manager.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000324-GPOS-00125"
  tag "gid": "V-73729"
  tag "rid": "SV-88393r1_rule"
  tag "stig_id": "WN16-UR-000010"
  tag "fix_id": "F-80179r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups are granted the \"Access Credential Manager as a
  trusted caller\" user right, this is a finding."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Access Credential Manager as a trusted caller\" to be defined but containing
  no entries (blank)."
  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should eq [] }
  end
end

      