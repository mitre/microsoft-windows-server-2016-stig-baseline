domain_role = command("wmic computersystem get domainrole | Findstr /v DomainRole").stdout.strip
control "V-73677" do
  title "Remote calls to the Security Account Manager (SAM) must be restricted
  to Administrators."
  desc  "The Windows Security Account Manager (SAM) stores users' passwords.
  Restricting Remote Procedure Call (RPC) connections to the SAM to
  Administrators helps protect those credentials."
  if domain_role != '4' && domain_role != '5'
    impact 0.5
  else
    impact 0.0
  end
  tag "gtitle": "SRG-OS-000324-GPOS-00125"
  tag "gid": "V-73677"
  tag "rid": "SV-88341r2_rule"
  tag "stig_id": "WN16-MS-000310"
  tag "fix_id": "F-80127r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "This applies to member servers and standalone systems; it is NA
  for domain controllers.

  If the following registry value does not exist or is not configured as
  specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

  Value Name: RestrictRemoteSAM

  Value Type: REG_SZ
  Value: O:BAG:BAD:(A;;RC;;;BA)"
  tag "fix": "Navigate to the policy Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> Security Options >> \"Network access:
  Restrict clients allowed to make remote calls to SAM\".
  Select \"Edit Security\" to configure the \"Security descriptor:\".

  Add \"Administrators\" in \"Group or user names:\" if it is not already listed
  (this is the default).

  Select \"Administrators\" in \"Group or user names:\".

  Select \"Allow\" for \"Remote Access\" in \"Permissions for \"Administrators\".

  Click \"OK\".

  The \"Security descriptor:\" must be populated with \"O:BAG:BAD:(A;;RC;;;BA)
  for the policy to be enforced."
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "RestrictRemoteSAM" }
    its("RestrictRemoteSAM") { should eq "O:BAG:BAD:(A;;RC;;;BA)" }
  end if domain_role != '4' && domain_role != '5'
  describe "System is a domain controller, control not applicable" do
    skip "System is a domain controller, control not applicable"
  end if domain_role == '4' || domain_role == '5'
end

