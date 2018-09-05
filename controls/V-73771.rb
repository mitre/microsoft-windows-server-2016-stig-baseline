domain_role = command("wmic computersystem get domainrole | Findstr /v DomainRole").stdout.strip
control "V-73771" do
  title "The Deny log on locally user right on member servers must be
  configured to prevent access from highly privileged domain accounts on domain
  systems and from unauthenticated access on all systems."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    The \"Deny log on locally\" user right defines accounts that are prevented
  from logging on interactively.

    In an Active Directory Domain, denying logons to the Enterprise Admins and
  Domain Admins groups on lower-trust systems helps mitigate the risk of
  privilege escalation from credential theft attacks, which could lead to the
  compromise of an entire domain.

    The Guests group must be assigned this right to prevent unauthenticated
  access.
  "
  if domain_role != '4' && domain_role != '5'
    impact 0.5
  else
    impact 0.0
  end
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-73771"
  tag "rid": "SV-88435r1_rule"
  tag "stig_id": "WN16-MS-000400"
  tag "fix_id": "F-80221r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "This applies to member servers and standalone systems. A
  separate version applies to domain controllers.

  Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If the following accounts or groups are not defined for the \"Deny log on
  locally\" user right, this is a finding.

  Domain Systems Only:
  - Enterprise Admins Group
  - Domain Admins Group

  Systems dedicated to the management of Active Directory (AD admin platforms,
  see V-36436 in the Active Directory Domain STIG) are exempt from this.

  All Systems:
  - Guests Group"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Deny log on locally\" to include the following:

  Domain Systems Only:
  - Enterprise Admins Group
  - Domain Admins Group

  Systems dedicated to the management of Active Directory (AD admin platforms,
  see V-36436 in the Active Directory Domain STIG) are exempt from this.

  All Systems:
  - Guests Group"
  is_domain = command("wmic computersystem get domain | FINDSTR /V Domain").stdout.strip
  administrator_group = command("net localgroup Administrators | Format-List | Findstr /V 'Alias Name Comment Members - command'").stdout.strip.split('\n')
  administrator_domain_group = command("net localgroup Administrators /DOMAIN | Format-List | Findstr /V 'Alias Name Comment Members - command request'").stdout.strip.split('\n')

  if is_domain == 'WORKGROUP'
    describe security_policy do
      its('SeDenyInteractiveLogonRight') { should eq ['S-1-5-32-546'] }
    end if domain_role != '4' && domain_role != '5'
      
  else  
    get_domain_sid = command("wmic useraccount get sid | FINDSTR /V SID | Select -First 2").stdout.strip
    domain_sid = get_domain_sid[9..40]
    describe security_policy do
      its('SeDenyInteractiveLogonRight') { should include "S-1-21-#{domain_sid}-512" }
    end  
    describe security_policy do
      its('SeDenyInteractiveLogonRight') { should include "S-1-21-#{domain_sid}-519" }
    end 
  end if domain_role != '4' && domain_role != '5'
  
  describe "System is a domain controller, control not applicable" do
    skip "System is a domain controller, control not applicable"
  end if domain_role == '4' || domain_role == '5'

end

