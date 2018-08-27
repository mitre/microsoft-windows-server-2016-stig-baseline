control "V-73587" do
  title "Users must be notified if a web-based program attempts to install
software."
  desc  "Web-based programs may attempt to install malicious software on a
system. Ensuring users are notified if a web-based program attempts to install
software allows them to refuse the installation."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73587"
  tag "rid": "SV-88251r1_rule"
  tag "stig_id": "WN16-CC-000470"
  tag "fix_id": "F-80037r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "The default behavior is for Internet Explorer to warn users and
select whether to allow or refuse installation when a web-based program
attempts to install software on the system.

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of \"0\", this is not a finding.

If it exists and is configured with a value of \"1\", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: SafeForScripting

Value Type: REG_DWORD
Value: 0x00000000 (0) (or if the Value Name does not exist)"
  tag "fix": "The default behavior is for Internet Explorer to warn users and
select whether to allow or refuse installation when a web-based program
attempts to install software on the system.

If this needs to be corrected, configure the policy value for Computer
Configuration >> Administrative Templates >> Windows Components >> Windows
Installer >> \"Prevent Internet Explorer security prompt for Windows Installer
scripts\" to \"Not Configured\" or \"Disabled\"."
describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer") do
    it { should have_property "SafeForScripting" }
    its("SafeForScripting") { should cmp == 0 }
  end
end

