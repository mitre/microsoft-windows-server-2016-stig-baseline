control 'V-73733' do
  title "The Access this computer from the network user right must only be
  assigned to the Administrators and Authenticated Users groups on member
  servers."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    Accounts with the Access this computer from the network user right may
  access resources on the system, and this right must be limited to those
  requiring it.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000080-GPOS-00048'
  tag "gid": 'V-73733'
  tag "rid": 'SV-88397r1_rule'
  tag "stig_id": 'WN16-MS-000340'
  tag "fix_id": 'F-80183r1_fix'
  tag "cci": ['CCI-000213']
  tag "nist": ['AC-3', 'Rev_4']
  tag "documentable": false
  desc "check", "This applies to member servers and standalone systems. A
  separate version applies to domain controllers.

  Verify the effective setting in Local Group Policy Editor.

  Run gpedit.msc.

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If any accounts or groups other than the following are granted the Access
  this computer from the network user right, this is a finding.

  - Administrators
  - Authenticated Users

  Systems dedicated to managing Active Directory (AD admin platforms, see V-36436
  in the Active Directory Domain STIG), must only allow Administrators, removing
  the Authenticated Users group.

  If an application requires this user right, this would not be a finding.

  Vendor documentation must support the requirement for having the user right.

  The requirement must be documented with the ISSO.

  The application account must meet requirements for application account
  passwords, such as length (WN16-00-000060) and required frequency of changes
  (WN16-00-000070)."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  Access this computer from the network to include only the following
  accounts or groups:

  - Administrators
  - Authenticated Users

  Systems dedicated to managing Active Directory (AD admin platforms, see V-36436
  in the Active Directory Domain STIG), must only allow Administrators, removing
  the Authenticated Users group."
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if !(domain_role == '4') && !(domain_role == '5')
    describe.one do
      describe security_policy do
        its('SeNetworkLogonRight') { should be_in ['S-1-5-11', 'S-1-5-32-544'] }
      end
      describe security_policy do
        its('SeNetworkLogonRight') { should eq [] }
      end
    end
  end

  if domain_role == '4' || domain_role == '5'
    impact 0.0
    desc 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers and standalone systems'
    describe 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers and standalone systems' do
      skip 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers and standalone systems'
    end
  end
end
