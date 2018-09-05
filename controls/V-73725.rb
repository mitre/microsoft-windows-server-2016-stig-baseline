control "V-73725" do
  title "The screen saver must be password protected."
  desc  "Unattended systems are susceptible to unauthorized use and must be
  locked when unattended. Enabling a password-protected screen saver to engage
  after a specified period of time helps protects critical and sensitive data
  from exposure to unauthorized personnel with physical access to the computer."
  impact 0.5
  tag "gtitle": "SRG-OS-000028-GPOS-00009"
  tag "gid": "V-73725"
  tag "rid": "SV-88389r1_rule"
  tag "stig_id": "WN16-UC-000020"
  tag "fix_id": "F-80175r1_fix"
  tag "cci": ["CCI-000056"]
  tag "nist": ["AC-11 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_CURRENT_USER
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Control
  Panel\\Desktop\\

  Value Name: ScreenSaverIsSecure

  Type: REG_SZ
  Value: 1"
  tag "fix": "Configure the policy value for User Configuration >>
  Administrative Templates >> Control Panel >> Personalization >> \"Password
  protect the screen saver\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Control
  Panel\\Desktop") do
    it { should have_property "ScreenSaverIsSecure" }
    its("ScreenSaverIsSecure") { should cmp == 1}
  end
end

