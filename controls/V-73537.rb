control "V-73537" do
  title "Users must be prompted to authenticate when the system wakes from
sleep (on battery)."
  desc  "A system that does not require authentication when resuming from sleep
may provide access to unauthorized users. Authentication must always be
required when accessing a system. This setting ensures users are prompted for a
password when the system wakes from sleep (on battery)."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73537"
  tag "rid": "SV-88197r1_rule"
  tag "stig_id": "WN16-CC-000210"
  tag "fix_id": "F-79979r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path:
\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

Value Name: DCSettingIndex

Type: REG_DWORD
Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >>
Administrative Templates >> System >> Power Management >> Sleep Settings >>
\"Require a password when a computer wakes (on battery)\" to \"Enabled\"."
describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51") do
    it { should have_property "DCSettingIndex" }
    its("DCSettingIndex") { should cmp == 1 }
  end
end

