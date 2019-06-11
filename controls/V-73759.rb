control 'V-73759' do
  title "The Deny access to this computer from the network user right on member
  servers must be configured to prevent access from highly privileged domain
  accounts and local accounts on domain systems, and from unauthenticated access
  on all systems."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    The Deny access to this computer from the network user right defines
  the accounts that are prevented from logging on from the network.

    In an Active Directory Domain, denying logons to the Enterprise Admins and
  Domain Admins groups on lower-trust systems helps mitigate the risk of
  privilege escalation from credential theft attacks, which could lead to the
  compromise of an entire domain.

    Local accounts on domain-joined systems must also be assigned this right to
  decrease the risk of lateral movement resulting from credential theft attacks.

    The Guests group must be assigned this right to prevent unauthenticated
  access.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000080-GPOS-00048'
  tag "gid": 'V-73759'
  tag "rid": 'SV-88423r1_rule'
  tag "stig_id": 'WN16-MS-000370'
  tag "fix_id": 'F-80209r1_fix'
  tag "cci": ['CCI-000213']
  tag "nist": ['AC-3', 'Rev_4']
  tag "documentable": false
  tag "check": "This applies to member servers and standalone systems. A
  separate version applies to domain controllers.

  Verify the effective setting in Local Group Policy Editor.

  Run gpedit.msc.

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If the following accounts or groups are not defined for the Deny access to
  this computer from the network user right, this is a finding.

  Domain Systems Only:
  - Enterprise Admins group
  - Domain Admins group
  - Local account and member of Administrators group or Local account
  (see Note below)

  All Systems:
  - Guests group

  Systems dedicated to the management of Active Directory (AD admin platforms,
  see V-36436 in the Active Directory Domain STIG) are exempt from denying the
  Enterprise Admins and Domain Admins groups.

  Note: These are built-in security groups. Local account is more restrictive
  but may cause issues on servers such as systems that provide failover
  clustering."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  Deny access to this computer from the network to include the following:

  Domain Systems Only:
  - Enterprise Admins group
  - Domain Admins group
  - Local account and member of Administrators group or Local account
  (see Note below)

  All Systems:
  - Guests group

  Systems dedicated to the management of Active Directory (AD admin platforms,
  see V-36436 in the Active Directory Domain STIG) are exempt from denying the
  Enterprise Admins and Domain Admins groups.

  Note: These are built-in security groups. Local account is more restrictive
  but may cause issues on servers such as systems that provide failover
  clustering."

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if ![4, 5].include? domain_role
    if is_domain == 'WORKGROUP'
      describe.one do
        describe security_policy do
          its('SeDenyNetworkLogonRight') { should eq ['S-1-5-32-546'] }
        end
        describe security_policy do
          its('SeDenyNetworkLogonRight') { should eq [] }
        end
      end

    else
      get_domain_sid = command('wmic useraccount get sid | FINDSTR /V SID | Select -First 2').stdout.strip
      domain_sid = get_domain_sid[9..40]
      describe security_policy do
        its('SeDenyNetworkLogonRight') { should include "S-1-21-#{domain_sid}-512" }
      end
      describe security_policy do
        its('SeDenyNetworkLogonRight') { should include "S-1-21-#{domain_sid}-519" }
      end
    end
  end

  if [4, 5].include? domain_role
    impact 0.0
    desc 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers and standalone systems'
    describe 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers and standalone systems' do
      skip 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers and standalone systems'
    end
  end
end
