domain_role = command("wmic computersystem get domainrole | Findstr /v DomainRole").stdout.strip

control "V-73541" do
  title "Unauthenticated Remote Procedure Call (RPC) clients must be restricted
  from connecting to the RPC server."
  desc  "Unauthenticated RPC clients may allow anonymous access to sensitive
  information. Configuring RPC to restrict unauthenticated RPC clients from
  connecting to the RPC server will prevent anonymous connections."
  if domain_role != '4' && domain_role != '5'
    impact 0.5
  else
    impact 0.0
  end
  tag "gtitle": "SRG-OS-000379-GPOS-00164"
  tag "gid": "V-73541"
  tag "rid": "SV-88203r1_rule"
  tag "stig_id": "WN16-MS-000040"
  tag "fix_id": "F-79983r1_fix"
  tag "cci": ["CCI-001967"]
  tag "nist": ["IA-3 (1)", "Rev_4"]
  tag "documentable": false
  tag "check": "This applies to member servers and standalone systems, It is NA
  for domain controllers.

  If the following registry value does not exist or is not configured as
  specified, this is a finding.

  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc\\

  Value Name:  RestrictRemoteClients

  Type:  REG_DWORD
  Value:  0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> System >> Remote Procedure Call >> \"Restrict
  Unauthenticated RPC clients\" to \"Enabled\" with \"Authenticated\" selected."
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc") do
    it { should have_property "RestrictRemoteClients" }
    its("RestrictRemoteClients") { should cmp == 1 }
  end if domain_role != '4' && domain_role != '5'
  describe "System is a domain controller, control not applicable" do
    skip "System is a domain controller, control not applicable"
  end if domain_role == '4' || domain_role == '5'
end

