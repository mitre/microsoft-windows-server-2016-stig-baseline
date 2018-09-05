domain_role = command("wmic computersystem get domainrole | Findstr /v DomainRole").stdout.strip
control "V-73769" do
  title "The Deny log on locally user right on domain controllers must be
  configured to prevent unauthenticated access."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    The \"Deny log on locally\" user right defines accounts that are prevented
  from logging on interactively.

    The Guests group must be assigned this right to prevent unauthenticated
  access.
  "
  if domain_role == '4' || domain_role == '5'
    impact 0.5
  else
    impact 0.0
  end
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-73769"
  tag "rid": "SV-88433r1_rule"
  tag "stig_id": "WN16-DC-000400"
  tag "fix_id": "F-80219r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "This applies to domain controllers. A separate version applies
  to other systems.

  Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If the following accounts or groups are not defined for the \"Deny log on
  locally\" user right, this is a finding.

  - Guests Group"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Deny log on locally\" to include the following:

  - Guests Group"
  describe security_policy do
    its('SeDenyInteractiveLogonRight') { should eq ['S-1-5-32-546'] }
  end if domain_role == '4' || domain_role == '5'
  
  describe "System is not a domain controller, control not applicable" do
    skip "System is not a domain controller, control not applicable"
  end if domain_role != '4' && domain_role != '5'
end