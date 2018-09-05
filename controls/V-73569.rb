control "V-73569" do
  title "Local drives must be prevented from sharing with Remote Desktop
  Session Hosts."
  desc  "Preventing users from sharing the local drives on their client
  computers with Remote Session Hosts that they access helps reduce possible
  exposure of sensitive data."
  impact 0.5
  tag "gtitle": "SRG-OS-000138-GPOS-00069"
  tag "gid": "V-73569"
  tag "rid": "SV-88233r1_rule"
  tag "stig_id": "WN16-CC-000380"
  tag "fix_id": "F-80019r1_fix"
  tag "cci": ["CCI-001090"]
  tag "nist": ["SC-4", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

  Value Name: fDisableCdm

  Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> Windows Components >> Remote Desktop Services >>
  Remote Desktop Session Host >> Device and Resource Redirection >> \"Do not
  allow drive redirection\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fDisableCdm" }
    its("fDisableCdm") { should cmp == 1 }
  end
end

