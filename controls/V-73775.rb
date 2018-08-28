domain_role = command("wmic computersystem get domainrole | Findstr /v DomainRole").stdout.strip

control "V-73775" do
  title "The Deny log on through Remote Desktop Services user right on member
  servers must be configured to prevent access from highly privileged domain
  accounts and all local accounts on domain systems and from unauthenticated
  access on all systems."
  desc  "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

  The \"Deny log on through Remote Desktop Services\" user right defines the
  accounts that are prevented from logging on using Remote Desktop Services.

  In an Active Directory Domain, denying logons to the Enterprise Admins and
  Domain Admins groups on lower-trust systems helps mitigate the risk of
  privilege escalation from credential theft attacks, which could lead to the
  compromise of an entire domain.

  Local accounts on domain-joined systems must also be assigned this right to
  decrease the risk of lateral movement resulting from credential theft attacks.

  The Guests group must be assigned this right to prevent unauthenticated
  access.
  "
  if domain_role != '4' || domain_role != '5'
    impact 0.5
  else
    impact 0.0
  end
  tag "gtitle": "SRG-OS-000297-GPOS-00115"
  tag "gid": "V-73775"
  tag "rid": "SV-88439r1_rule"
  tag "stig_id": "WN16-MS-000410"
  tag "fix_id": "F-80225r1_fix"
  tag "cci": ["CCI-002314"]
  tag "nist": ["AC-17 (1)", "Rev_4"]
  tag "documentable": false
  tag "check": "This applies to member servers and standalone systems. A
  separate version applies to domain controllers.

  Verify the effective setting in Local Group Policy Editor.

  Run \"gpedit.msc\".

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If the following accounts or groups are not defined for the \"Deny log on
  through Remote Desktop Services\" user right, this is a finding.

  Domain Systems Only:
  - Enterprise Admins group
  - Domain Admins group
  - Local account (see Note below)

  All Systems:
  - Guests group

  Note: \"Local account\" is referring to the Windows built-in security group.

  Systems dedicated to the management of Active Directory (AD admin platforms,
  see V-36436 in the Active Directory Domain STIG) are exempt from denying the
  Enterprise Admins and Domain Admins groups."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  \"Deny log on through Remote Desktop Services\" to include the following:

  Domain Systems Only:
  - Enterprise Admins group
  - Domain Admins group
  - Local account (see Note below)

  All Systems:
  - Guests group

  Note: \"Local account\" is referring to the Windows built-in security group.

  Systems dedicated to the management of Active Directory (AD admin platforms,
  see V-36436 in the Active Directory Domain STIG) are exempt from denying the
  Enterprise Admins and Domain Admins groups."
  is_domain = command("wmic computersystem get domain | FINDSTR /V Domain").stdout.strip
  administrator_group = command("net localgroup Administrators | Format-List | Findstr /V 'Alias Name Comment Members - command'").stdout.strip.split('\n')
  administrator_domain_group = command("net localgroup Administrators /DOMAIN | Format-List | Findstr /V 'Alias Name Comment Members - command request'").stdout.strip.split('\n')

  if is_domain == 'WORKGROUP'
    describe security_policy do
      its('SeDenyRemoteInteractiveLogonRight') { should eq ['S-1-5-32-546'] }
     end if domain_role == '4' || domain_role == '5'
      
  else  
    get_domain_sid = command("wmic useraccount get sid | FINDSTR /V SID | Select -First 2").stdout.strip
    domain_sid = get_domain_sid[9..40]
    describe security_policy do
      its('SeDenyRemoteInteractiveLogonRight') { should include "S-1-21-#{domain_sid}-512" }
    end  
    describe security_policy do
      its('SeDenyRemoteInteractiveLogonRight') { should include "S-1-21-#{domain_sid}-519" }
    end 
    describe security_policy do
      its('SeDenyRemoteInteractiveLogonRight') { should include 'S-1-2-0' }
    end 
  end if domain_role == '4' || domain_role == '5'

  describe "System is not a domain controller, control not applicable" do
    skip "System is not a domain controller, control not applicable"
  end if domain_role != '4' || domain_role != '5'

end

