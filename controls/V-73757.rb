domain_role = command("wmic computersystem get domainrole | Findstr /v DomainRole").stdout.strip
control "V-73757" do
  title "The Deny access to this computer from the network user right on domain
  controllers must be configured to prevent unauthenticated access."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    The \"Deny access to this computer from the network\" user right defines
  the accounts that are prevented from logging on from the network.

    The Guests group must be assigned this right to prevent unauthenticated
  access.
  "
  if domain_role == '4' || domain_role == '5'
    impact 0.5
  else
    impact 0.0
  end
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-73757"
  tag "rid": "SV-88421r1_rule"
  tag "stig_id": "WN16-DC-000370"
  tag "fix_id": "F-80207r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "This applies to domain controllers. A separate version applies
  to other systems.

  Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If the following accounts or groups are not defined for the \"Deny access to
  this computer from the network\" user right, this is a finding.

  - Guests Group"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Deny access to this computer from the network\" to include the following:

  - Guests Group"
  describe security_policy do
    its('SeDenyNetworkLogonRight') { should eq ['S-1-5-32-546'] }
  end if domain_role == '4' || domain_role == '5'
  
  describe "System is not a domain controller, control not applicable" do
    skip "System is not a domain controller, control not applicable"
  end if domain_role != '4' && domain_role != '5'
end

      
