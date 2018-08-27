control "V-73721" do
  title "User Account Control must virtualize file and registry write failures
to per-user locations."
  desc  "User Account Control (UAC) is a security mechanism for limiting the
elevation of privileges, including administrative accounts, unless authorized.
This setting configures non-UAC-compliant applications to run in virtualized
file and registry entries in per-user locations, allowing them to run."
  impact 0.5
  tag "gtitle": "SRG-OS-000134-GPOS-00068"
  tag "gid": "V-73721"
  tag "rid": "SV-88385r1_rule"
  tag "stig_id": "WN16-SO-000530"
  tag "fix_id": "F-80171r1_fix"
  tag "cci": ["CCI-001084"]
  tag "nist": ["SC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "UAC requirements are NA for Server Core installations (this is
the default installation option for Windows Server 2016 versus Server with
Desktop Experience) as well as Nano Server.

If the following registry value does not exist or is not configured as
specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path:
\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableVirtualization

Value Type: REG_DWORD
Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> Security Options >> \"User
Account Control: Virtualize file and registry write failures to per-user
locations\" to \"Enabled\"."
describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "EnableVirtualization" }
    its("EnableVirtualization") { should cmp == 1 }
  end
end

