control "V-73703" do
  title "Windows Server 2016 must be configured to require case insensitivity
  for non-Windows subsystems."
  desc  "This setting controls the behavior of non-Windows subsystems when
  dealing with the case of arguments or commands. Case sensitivity could lead to
  the access of files or commands that must be restricted. To prevent this from
  happening, case insensitivity restrictions must be required."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73703"
  tag "rid": "SV-88367r1_rule"
  tag "stig_id": "WN16-SO-000440"
  tag "fix_id": "F-80153r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel\\

  Value Name: ObCaseInsensitive

  Value Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >> \"System
  objects: Require case insensitivity for non-Windows subsystems\" to
  \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel") do
    it { should have_property "ObCaseInsensitive" }
    its("ObCaseInsensitive") { should cmp == 1 }
  end
end

