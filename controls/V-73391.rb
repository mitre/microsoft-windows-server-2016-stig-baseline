control 'V-73391' do
  title "The Active Directory Domain object must be configured with proper
  audit settings."
  desc  "When inappropriate audit settings are configured for directory service
  database objects, it may be possible for a user or process to update the data
  without generating any tracking data. The impact of missing audit data is
  related to the type of object. A failure to capture audit data for objects used
  by identification, authentication, or authorization functions could degrade or
  eliminate the ability to track changes to access policy for systems or data.

      For Active Directory (AD), there are a number of critical object types in
  the domain naming context of the AD database for which auditing is essential.
  This includes the Domain object. Because changes to these objects can
  significantly impact access controls or the availability of systems, the
  absence of auditing data makes it impossible to identify the source of changes
  that impact the confidentiality, integrity, and availability of data and
  systems throughout an AD domain. The lack of proper auditing can result in
  insufficient forensic evidence needed to investigate an incident and prosecute
  the intruder.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000327-GPOS-00127'
  tag "satisfies": ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000458-GPOS-00203',
                    'SRG-OS-000463-GPOS-00207', 'SRG-OS-000468-GPOS-00212']
  tag "gid": 'V-73391'
  tag "rid": 'SV-88043r1_rule'
  tag "stig_id": 'WN16-DC-000180'
  tag "fix_id": 'F-79833r1_fix'
  tag "cci": ['CCI-000172', 'CCI-002234']
  tag "nist": ['AU-12 c', 'AC-6 (9)', 'Rev_4']
  tag "documentable": false
  tag "check": "This applies to domain controllers. It is NA for other systems.

  Review the auditing configuration for the Domain object.

  Open Active Directory Users and Computers (available from various menus or
  run dsa.msc).

  Ensure Advanced Features is selected in the View menu.

  Select the domain being reviewed in the left pane.

  Right-click the domain name and select Properties.

  Select the Security tab.

  Select the Advanced button and then the Auditing tab.

  If the audit settings on the Domain object are not at least as inclusive as
  those below, this is a finding.

  Type - Fail
  Principal - Everyone
  Access - Full Control
  Inherited from - None
  Applies to - This object only

  The success types listed below are defaults. Where Special is listed in the
  summary screens for Access, detailed Permissions are provided for reference.
  Various Properties selections may also exist by default.

  Two instances with the following summary information will be listed.

  Type - Success
  Principal - Everyone
  Access - (blank)
  Inherited from - None
  Applies to - Special

  Type - Success
  Principal - Domain Users
  Access - All extended rights
  Inherited from - None
  Applies to - This object only

  Type - Success
  Principal - Administrators
  Access - All extended rights
  Inherited from - None
  Applies to - This object only

  Type - Success
  Principal - Everyone
  Access - Special
  Inherited from - None
  Applies to - This object only
  (Access - Special = Permissions: Write all properties, Modify permissions,
  Modify owner)"
  tag "fix": "Open Active Directory Users and Computers (available from
  various menus or run dsa.msc).

  Ensure Advanced Features is selected in the View menu.

  Select the domain being reviewed in the left pane.

  Right-click the domain name and select Properties.

  Select the Security tab.

  Select the Advanced button and then the Auditing tab.

  Configure the audit settings for Domain object to include the following.

  Type - Fail
  Principal - Everyone
  Access - Full Control
  Inherited from - None
  Applies to - This object only

  The success types listed below are defaults. Where Special is listed in the
  summary screens for Access, detailed Permissions are provided for reference.
  Various Properties selections may also exist by default.

  Two instances with the following summary information will be listed.

  Type - Success
  Principal - Everyone
  Access - (blank)
  Inherited from - None
  Applies to - Special

  Type - Success
  Principal - Domain Users
  Access - All extended rights
  Inherited from - None
  Applies to - This object only

  Type - Success
  Principal - Administrators
  Access - All extended rights
  Inherited from - None
  Applies to - This object only

  Type - Success
  Principal - Everyone
  Access - Special
  Inherited from - None
  Applies to - This object only
  (Access - Special = Permissions: Write all properties, Modify permissions,
  Modify owner.)"
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    distinguishedName = json(command: '(Get-ADDomain).DistinguishedName | ConvertTo-JSON').params
    netbiosname = json(command: 'Get-ADDomain | Select NetBIOSName | ConvertTo-JSON').params['NetBIOSName']
    acl_rules = json(command: "(Get-ACL -Audit -Path AD:'#{distinguishedName}').Audit | ConvertTo-CSV | ConvertFrom-CSV | ConvertTo-JSON").params

    acl_rules.each do |acl_rule|
      principal = acl_rule['IdentityReference']
      type = acl_rule['AuditFlags']
      is_inherited = acl_rule['IsInherited']
      access = acl_rule['ActiveDirectoryRights'].parse_csv.collect{|x| x.strip || x}
      inheritance = acl_rule['InheritanceFlags']
      propogation = acl_rule['PropogationFlags']
      
      describe "The audit entry 'Inherited from' for principal: #{principal}" do
        subject { is_inherited }
        it { should cmp "False" }
      end
      describe "The audit entry 'Applies to'(PropogationFlags) for principal: #{principal}" do
        subject { propogation }
        it { should cmp nil }
      end

      if type == "Fail"
        describe "The audit entry 'Type' for principal: #{principal}" do
          subject { type }
          it { should cmp "Fail" }
        end
        describe "The audit entry 'Access' for Principal: #{principal}" do
          subject { ["GenericAll"] }
          it { should be_in access }
        end
        describe "The audit entry 'Applies to'(InheritanceFlags) for principal: #{principal}" do
          subject { inheritance }
          it { should cmp "None" }
        end
      elsif type == "Success"
        describe "The audit entry 'Type' for principal: #{principal}" do
          subject { type }
          it { should cmp "Success" }
        end
        if principal == "BUILTIN\\Administrators" || principal == "#{netbiosname}\\Domain Users"
          describe "The audit entry 'Access' for Principal: #{principal}" do
            subject { ["ExtendedRight"] }
            it { should be_in access }
          end
          describe "The audit entry 'Applies to'(InheritanceFlags) for principal: #{principal}" do
            subject { inheritance }
            it { should cmp "None" }
          end
        end
  
        if principal == "Everyone"
          if inheritance == "None"
            describe "The audit entry 'Access' for Principal: #{principal}" do
              subject { ["WriteProperty", "WriteDacl", "WriteOwner"] }
              it { should be_in access }
            end
            describe "The audit entry 'Applies to'(InheritanceFlags) for principal: #{principal}" do
              subject { inheritance }
              it { should cmp "None" }
            end
          elsif 
            describe "The audit entry 'Access' for Principal: #{principal}" do
              subject { ["WriteProperty"] }
              it { should be_in access }
            end
            describe "The audit entry 'Applies to'(InheritanceFlags) for principal: #{principal}" do
              subject { inheritance }
              it { should cmp "ContainerInherit" }
            end
          end
        end
      end

    end
  else
    impact 0.0
    desc 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end


end
