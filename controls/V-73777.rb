control 'V-73777' do
  title "The Enable computer and user accounts to be trusted for delegation
  user right must only be assigned to the Administrators group on domain
  controllers."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    The \"Enable computer and user accounts to be trusted for delegation\" user
  right allows the \"Trusted for Delegation\" setting to be changed. This could
  allow unauthorized users to impersonate other users.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000324-GPOS-00125'
  tag "gid": 'V-73777'
  tag "rid": 'SV-88441r1_rule'
  tag "stig_id": 'WN16-DC-000420'
  tag "fix_id": 'F-80227r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "This applies to domain controllers. A separate version applies
to other systems.

Verify the effective setting in Local Group Policy Editor.

Run \"gpedit.msc\".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the \"Enable
computer and user accounts to be trusted for delegation\" user right, this is a
finding.

- Administrators"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Enable computer and user accounts to be trusted for delegation\" to include
  only the following accounts or groups:

  - Administrators"
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if [4, 5].include? domain_role
    describe.one do
      describe security_policy do
        its('SeEnableDelegationPrivilege') { should eq ['S-1-5-32-544'] }
      end
      describe security_policy do
        its('SeEnableDelegationPrivilege') { should eq [] }
      end
    end
  end

  if ![4, 5].include? domain_role
    impact 0.0
    desc 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end
