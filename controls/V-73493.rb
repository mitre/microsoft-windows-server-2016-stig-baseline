control "V-73493" do
  title "The display of slide shows on the lock screen must be disabled."
  desc  "Slide shows that are displayed on the lock screen could display
sensitive information to unauthorized personnel. Turning off this feature will
limit access to the information to a logged-on user."
  impact 0.5
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": "V-73493"
  tag "rid": "SV-88145r1_rule"
  tag "stig_id": "WN16-CC-000010"
  tag "fix_id": "F-79935r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the registry value below.

If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\\

Value Name: NoLockScreenSlideshow

Value Type: REG_DWORD
Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >>
Administrative Templates >> Control Panel >> Personalization >> \"Prevent
enabling lock screen slide show\" to \"Enabled\"."
describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization") do
    it { should have_property "NoLockScreenSlideshow" }
    its("NoLockScreenSlideshow") { should cmp == 1 }
  end
end

