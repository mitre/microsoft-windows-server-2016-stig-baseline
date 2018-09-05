domain_role = command("wmic computersystem get domainrole | Findstr /v DomainRole").stdout.strip
control "V-73741" do
  title "The Allow log on through Remote Desktop Services user right must only
  be assigned to the Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    Accounts with the \"Allow log on through Remote Desktop Services\" user
  right can access a system through Remote Desktop.
  "
  if domain_role == '4' || domain_role == '5'
    impact 0.5
  else
    impact 0.0
  end
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-73741"
  tag "rid": "SV-88405r1_rule"
  tag "stig_id": "WN16-DC-000360"
  tag "fix_id": "F-80191r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "This applies to domain controllers, it is NA for other systems.

  Verify the effective setting in Local Group Policy Editor.
  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups other than the following are granted the \"Allow log
  on through Remote Desktop Services\" user right, this is a finding.

  - Administrators"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Allow log on through Remote Desktop Services\" to include only the following
  accounts or groups:

  - Administrators"
  describe security_policy do 
    its('SeRemoteInteractiveLogonRight') { should eq ['S-1-5-32-544'] }
  end if domain_role == '4' || domain_role == '5'
  
  describe "System is not a domain controller, control not applicable" do
    skip "System is not a domain controller, control not applicable"
  end if domain_role != '4' && domain_role != '5'
end

     