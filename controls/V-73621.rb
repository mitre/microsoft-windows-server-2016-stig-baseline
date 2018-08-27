control "V-73621" do
  title "Local accounts with blank passwords must be restricted to prevent
access from the network."
  desc  "An account without a password can allow unauthorized access to a
system as only the username would be required. Password policies should prevent
accounts with blank passwords from existing on a system. However, if a local
account with a blank password does exist, enabling this setting will prevent
network access, limiting the account to local console logon only."
  impact 0.7
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73621"
  tag "rid": "SV-88285r1_rule"
  tag "stig_id": "WN16-SO-000020"
  tag "fix_id": "F-80071r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: LimitBlankPasswordUse

Value Type: REG_DWORD
Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> Security Options >>
\"Accounts: Limit local account use of blank passwords to console logon only\"
to \"Enabled\"."
 describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentcontrolSet\\Control\\Lsa") do
    it { should have_property "LimitBlankPasswordUse" }
    its("LimitBlankPasswordUse") { should cmp == 1 }
  end
end

