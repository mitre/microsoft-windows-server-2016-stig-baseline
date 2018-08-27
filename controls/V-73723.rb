control "V-73723" do
  title "A screen saver must be enabled on the system."
  desc  "Unattended systems are susceptible to unauthorized use and must be
locked when unattended. Enabling a password-protected screen saver to engage
after a specified period of time helps protects critical and sensitive data
from exposure to unauthorized personnel with physical access to the computer."
  impact 0.5
  tag "gtitle": "SRG-OS-000031-GPOS-00012"
  tag "gid": "V-73723"
  tag "rid": "SV-88387r1_rule"
  tag "stig_id": "WN16-UC-000010"
  tag "fix_id": "F-80173r1_fix"
  tag "cci": ["CCI-000060"]
  tag "nist": ["AC-11 (1)", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
configured as specified, this is a finding.

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Control
Panel\\Desktop\\

Value Name: ScreenSaveActive

Type: REG_SZ
Value: 1

Applications requiring continuous, real-time screen display (e.g., network
management products) require the following and must be documented with the ISSO:

- The logon session does not have administrator rights.
- The display station (e.g., keyboard, monitor, etc.) is located in a
controlled access area."
  tag "fix": "Configure the policy value for User Configuration >>
Administrative Templates >> Control Panel >> Personalization >> \"Enable screen
saver\" to \"Enabled\"."
describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Control
  Panel\\Desktop") do
    it { should have_property "ScreenSaveActive" }
    its("ScreenSaveActive") { should cmp == 1 }
  end
end

