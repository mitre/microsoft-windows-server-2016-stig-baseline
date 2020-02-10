control 'V-73373' do
  title "Active Directory Group Policy objects must have proper access control
  permissions."
  desc "When directory service database objects do not have appropriate access
  control permissions, it may be possible for malicious users to create, read,
  update, or delete the objects and degrade or destroy the integrity of the data.
  When the directory service is used for identification, authentication, or
  authorization functions, a compromise of the database objects could lead to a
  compromise of all systems relying on the directory service.

      For Active Directory (AD), the Group Policy objects require special
  attention. In a distributed administration model (i.e., help desk), Group
  Policy objects are more likely to have access permissions changed from the
  secure defaults. If inappropriate access permissions are defined for Group
  Policy objects, this could allow an intruder to change the security policy
  applied to all domain client computers (workstations and servers).
  "
  impact 0.7
  tag "gtitle": 'SRG-OS-000324-GPOS-00125'
  tag "gid": 'V-73373'
  tag "rid": 'SV-88025r1_rule'
  tag "stig_id": 'WN16-DC-000090'
  tag "fix_id": 'F-79815r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "This applies to domain controllers. It is NA for other systems.

  Review the permissions on Group Policy objects.

  Open Group Policy Management (available from various menus or run
  gpmc.msc).

  Navigate to Group Policy Objects in the domain being reviewed (Forest >>
  Domains >> Domain).

  For each Group Policy object:

  Select the Group Policy object item in the left pane.

  Select the Delegation tab in the right pane.

  Select the Advanced button.

  Select each Group or user name.

  View the permissions.

  If any standard user accounts or groups have Allow permissions greater than
  Read and Apply group policy, this is a finding.

  Other access permissions that allow the objects to be updated are considered
  findings unless specifically documented by the ISSO.

  The default permissions noted below satisfy this requirement.

  The permissions shown are at the summary level. More detailed permissions can
  be viewed by selecting the next Advanced button, the desired Permission
  entry, and the Edit button.

  Authenticated Users - Read, Apply group policy, Special permissions

  The special permissions for Authenticated Users are for Read-type Properties.
  If detailed permissions include any Create, Delete, Modify, or Write
  Permissions or Properties, this is a finding.

  The special permissions for the following default groups are not the focus of
  this requirement and may include a wide range of permissions and properties.

  CREATOR OWNER - Special permissions
  SYSTEM - Read, Write, Create all child objects, Delete all child objects,
  Special permissions
  Domain Admins - Read, Write, Create all child objects, Delete all child
  objects, Special permissions
  Enterprise Admins - Read, Write, Create all child objects, Delete all child
  objects, Special permissions
  ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions

  The Domain Admins and Enterprise Admins will not have the Delete all child
  objects permission on the two default Group Policy objects: Default Domain
  Policy and Default Domain Controllers Policy. They will have this permission on
  organization created Group Policy objects."
  tag "fix": "Maintain the permissions on Group Policy objects to not allow
  greater than Read and Apply group policy for standard user accounts or
  groups. The default permissions below meet this requirement.

  Authenticated Users - Read, Apply group policy, Special permissions

  The special permissions for Authenticated Users are for Read-type Properties.

  CREATOR OWNER - Special permissions
  SYSTEM - Read, Write, Create all child objects, Delete all child objects,
  Special permissions
  Domain Admins - Read, Write, Create all child objects, Delete all child
  objects, Special permissions
  Enterprise Admins - Read, Write, Create all child objects, Delete all child
  objects, Special permissions
  ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions

  Document any other access permissions that allow the objects to be updated with
  the ISSO.

  The Domain Admins and Enterprise Admins will not have the Delete all child
  objects permission on the two default Group Policy objects: Default Domain
  Policy and Default Domain Controllers Policy. They will have this permission on
  created Group Policy objects."
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if domain_role == '4' || domain_role == '5'
    perms_query = <<-FOO
    $gpos = Get-GPO -All;
    $info = foreach ($gpo in $gpos) {
      Get-GPPermissions -Guid $gpo.Id -All | Select-Object `
      @{n='GPOName';e={$gpo.DisplayName}},
      @{n='AccountName';e={$_.Trustee.Name}},
      @{n='Permissions';e={$_.Permission}}
    };
    $info | ConvertTo-CSV | ConvertFrom-CSV | ConvertTo-JSON;
    FOO
    permissions = json(command: perms_query).params

    describe.one do
      permissions.each do |perm|
        describe "The #{perm['GPOName']} gpo's permission property for #{perm['AccountName']} group/account" do
          subject { perm }
          its(['AccountName']) { should cmp "Domain Admins" }
          if perm['GPOName'] == "Default Domain Policy" || perm['GPOName'] == "Default Domain Controllers Policy"
            its(['Permissions']) { should cmp "GpoCustom" }
            its(['Permissions']) { should_not cmp "GpoEditDeleteModifySecurity" }
          else
            its(['Permissions']) { should cmp "GpoEditDeleteModifySecurity" }
          end
        end
      end
    end

    describe.one do
      permissions.each do |perm|
        describe "The #{perm['GPOName']} gpo's permission property for #{perm['AccountName']} group/account" do
          subject { perm }
          its(['AccountName']) { should cmp "Enterprise Admins" }
          if perm['GPOName'] == "Default Domain Policy" || perm['GPOName'] == "Default Domain Controllers Policy"
            its(['Permissions']) { should cmp "GpoCustom" }
            its(['Permissions']) { should_not cmp "GpoEditDeleteModifySecurity" }
          else
            its(['Permissions']) { should cmp "GpoEditDeleteModifySecurity" }
          end
        end
      end
    end

    describe.one do
      permissions.each do |perm|
        describe "The #{perm['GPOName']} gpo's permission property for #{perm['AccountName']} group/account" do
          subject { perm }
          its(['AccountName']) { should cmp "SYSTEM" }
          its(['Permissions']) { should cmp "GpoEditDeleteModifySecurity" }
        end
      end
    end

    describe.one do
      permissions.each do |perm|
        describe "The #{perm['GPOName']} gpo's permission property for #{perm['AccountName']} group/account" do
          subject { perm }
          its(['AccountName']) { should cmp "Authenticated Users" }
          its(['Permissions']) { should cmp "GpoApply" }
        end
      end
    end

    describe.one do
      permissions.each do |perm|
        describe "The #{perm['GPOName']} gpo's permission property for #{perm['AccountName']} group/account" do
          subject { perm }
          its(['AccountName']) { should cmp "ENTERPRISE DOMAIN CONTROLLERS" }
          its(['Permissions']) { should cmp "GpoRead" }
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
