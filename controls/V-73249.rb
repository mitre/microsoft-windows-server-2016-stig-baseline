control 'V-73249' do
  title "Permissions for the system drive root directory (usually C:\\) must
  conform to minimum requirements."
  desc "Changing the system's file and directory permissions allows the
  possibility of unauthorized and anonymous modification to the operating system
  and installed applications.

  The default permissions are adequate when the Security Option Network
  access: Let everyone permissions apply to anonymous users is set to
  Disabled (WN16-SO-000290).
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000312-GPOS-00122'
  tag "satisfies": ['SRG-OS-000312-GPOS-00122', 'SRG-OS-000312-GPOS-00123',
                    'SRG-OS-000312-GPOS-00124']
  tag "gid": 'V-73249'
  tag "rid": 'SV-87901r1_rule'
  tag "stig_id": 'WN16-00-000160'
  tag "fix_id": 'F-79693r1_fix'
  tag "cci": ['CCI-002165']
  tag "nist": ['AC-3 (4)', 'Rev_4']
  tag "documentable": false
  desc "check", "The default permissions are adequate when the Security Option
  Network access: Let everyone permissions apply to anonymous users is set to
  Disabled (WN16-SO-000290).

  Review the permissions for the system drive's root directory (usually C:\\).
  Non-privileged groups such as Users or Authenticated Users must not have
  greater than Read & execute permissions except where noted as defaults.
  (Individual accounts must not be used to assign permissions.)

  If permissions are not as restrictive as the default permissions listed below,
  this is a finding.

  Viewing in File Explorer:

  View the Properties of the system drive's root directory.

  Select the Security tab, and the Advanced button.

  Default permissions:
  C:\\
  Type - Allow for all
  Inherited from - None for all

  Principal - Access - Applies to

  SYSTEM - Full control - This folder, subfolders, and files
  Administrators - Full control - This folder, subfolders, and files
  Users - Read & execute - This folder, subfolders, and files
  Users - Create folders/append data - This folder and subfolders
  Users - Create files/write data - Subfolders only
  CREATOR OWNER - Full Control - Subfolders and files only

  Alternately, use icacls:

  Open Command Prompt (Admin).

  Enter icacls followed by the directory:

  icacls c:\\

  The following results should be displayed:

  c:\\
  NT AUTHORITY\\SYSTEM:(OI)(CI)(F)
  BUILTIN\\Administrators:(OI)(CI)(F)
  BUILTIN\\Users:(OI)(CI)(RX)
  BUILTIN\\Users:(CI)(AD)
  BUILTIN\\Users:(CI)(IO)(WD)
  CREATOR OWNER:(OI)(CI)(IO)(F)
  Successfully processed 1 files; Failed processing 0 files"
  desc "fix", "Maintain the default permissions for the system drive's root
  directory and configure the Security Option Network access: Let everyone
  permissions apply to anonymous users to Disabled (WN16-SO-000290).

  Default Permissions
  C:\\
  Type - Allow for all
  Inherited from - None for all

  Principal - Access - Applies to

  SYSTEM - Full control - This folder, subfolders, and files
  Administrators - Full control - This folder, subfolders, and files
  Users - Read & execute - This folder, subfolders, and files
  Users - Create folders/append data - This folder and subfolders
  Users - Create files/write data - Subfolders only
  CREATOR OWNER - Full Control - Subfolders and files only"

  paths = [
    "C:\\"
  ]

  paths.each do |path|
    acl_rules = json(command: "(Get-ACL -Path '#{path}').Access | ConvertTo-CSV | ConvertFrom-CSV | ConvertTo-JSON").params

    describe.one do
      acl_rules.each do |acl_rule|
        describe "The '#{path}' folder\'s access rule property:" do
          subject { acl_rule }
          its(['FileSystemRights']) { should cmp "FullControl" }
          its(['AccessControlType']) { should cmp "Allow" }
          its(['IdentityReference']) { should cmp "NT AUTHORITY\\SYSTEM" }
          its(['IsInherited']) { should cmp "False" }
          its(['InheritanceFlags']) { should cmp "ContainerInherit, ObjectInherit" }
          its(['PropagationFlags']) { should cmp "None" }
        end
      end
    end

    describe.one do
      acl_rules.each do |acl_rule|
        describe "The '#{path}' folder\'s access rule property:" do
          subject { acl_rule }
          its(['FileSystemRights']) { should cmp "FullControl" }
          its(['AccessControlType']) { should cmp "Allow" }
          its(['IdentityReference']) { should cmp "BUILTIN\\Administrators" }
          its(['IsInherited']) { should cmp "False" }
          its(['InheritanceFlags']) { should cmp "ContainerInherit, ObjectInherit" }
          its(['PropagationFlags']) { should cmp "None" }
        end
      end
    end

    describe.one do
      acl_rules.each do |acl_rule|
        describe "The '#{path}' folder\'s access rule property:" do
          subject { acl_rule }
          its(['FileSystemRights']) { should cmp "ReadAndExecute, Synchronize" }
          its(['AccessControlType']) { should cmp "Allow" }
          its(['IdentityReference']) { should cmp "BUILTIN\\Users" }
          its(['IsInherited']) { should cmp "False" }
          its(['InheritanceFlags']) { should cmp "ContainerInherit, ObjectInherit" }
          its(['PropagationFlags']) { should cmp "None" }
        end
      end
    end

    describe.one do
      acl_rules.each do |acl_rule|
        describe "The '#{path}' folder\'s access rule property:" do
          subject { acl_rule }
          its(['FileSystemRights']) { should cmp "AppendData" }
          its(['AccessControlType']) { should cmp "Allow" }
          its(['IdentityReference']) { should cmp "BUILTIN\\Users" }
          its(['IsInherited']) { should cmp "False" }
          its(['InheritanceFlags']) { should cmp "ContainerInherit" }
          its(['PropagationFlags']) { should cmp "None" }
        end
      end
    end

    describe.one do
      acl_rules.each do |acl_rule|
        describe "The '#{path}' folder\'s access rule property:" do
          subject { acl_rule }
          its(['FileSystemRights']) { should cmp "CreateFiles" }
          its(['AccessControlType']) { should cmp "Allow" }
          its(['IdentityReference']) { should cmp "BUILTIN\\Users" }
          its(['IsInherited']) { should cmp "False" }
          its(['InheritanceFlags']) { should cmp "ContainerInherit" }
          its(['PropagationFlags']) { should cmp "InheritOnly" }
        end
      end
    end

    describe.one do
      acl_rules.each do |acl_rule|
        describe "The '#{path}' folder\'s access rule property:" do
          subject { acl_rule }
          its(['FileSystemRights']) { should cmp "268435456" }
          its(['AccessControlType']) { should cmp "Allow" }
          its(['IdentityReference']) { should cmp "CREATOR OWNER" }
          its(['IsInherited']) { should cmp "False" }
          its(['InheritanceFlags']) { should cmp "ContainerInherit, ObjectInherit" }
          its(['PropagationFlags']) { should cmp "InheritOnly" }
        end
      end
    end
  end

  
end
