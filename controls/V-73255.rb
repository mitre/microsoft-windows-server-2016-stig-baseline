control 'V-73255' do
  title "Default permissions for the HKEY_LOCAL_MACHINE registry hive must be
  maintained."
  desc "The registry is integral to the function, security, and stability of
  the Windows system. Changing the system's registry permissions allows the
  possibility of unauthorized and anonymous modification to the operating system."
  impact 0.5
  tag "gtitle": 'SRG-OS-000324-GPOS-00125'
  tag "gid": 'V-73255'
  tag "rid": 'SV-87907r1_rule'
  tag "stig_id": 'WN16-00-000190'
  tag "fix_id": 'F-79699r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "Review the registry permissions for the keys of the
  HKEY_LOCAL_MACHINE hive noted below.

  If any non-privileged groups such as Everyone, Users, or Authenticated Users
  have greater than Read permission, this is a finding.

  If permissions are not as restrictive as the default permissions listed below,
  this is a finding.

  Run Regedit.

  Right-click on the registry areas noted below.

  Select Permissions... and the Advanced button.

  HKEY_LOCAL_MACHINE\\SECURITY

  Type - Allow for all
  Inherited from - None for all
  Principal - Access - Applies to
  SYSTEM - Full Control - This key and subkeys
  Administrators - Special - This key and subkeys

  HKEY_LOCAL_MACHINE\\SOFTWARE

  Type - Allow for all
  Inherited from - None for all
  Principal - Access - Applies to
  Users - Read - This key and subkeys
  Administrators - Full Control - This key and subkeys
  SYSTEM - Full Control - This key and subkeys
  CREATOR OWNER - Full Control - This key and subkeys
  ALL APPLICATION PACKAGES - Read - This key and subkeys

  HKEY_LOCAL_MACHINE\\SYSTEM

  Type - Allow for all
  Inherited from - None for all
  Principal - Access - Applies to
  Users - Read - This key and subkeys
  Administrators - Full Control - This key and subkeys
  SYSTEM - Full Control - This key and subkeys
  CREATOR OWNER - Full Control - Subkeys only
  ALL APPLICATION PACKAGES - Read - This key and subkeys

  Other examples under the noted keys may also be sampled. There may be some
  instances where non-privileged groups have greater than Read permission.

  If the defaults have not been changed, these are not a finding."
  tag "fix": "Maintain the default permissions for the HKEY_LOCAL_MACHINE
  registry hive.

  The default permissions of the higher-level keys are noted below.

  HKEY_LOCAL_MACHINE\\SECURITY

  Type - Allow for all
  Inherited from - None for all
  Principal - Access - Applies to
  SYSTEM - Full Control - This key and subkeys
  Administrators - Special - This key and subkeys

  HKEY_LOCAL_MACHINE\\SOFTWARE

  Type - Allow for all
  Inherited from - None for all
  Principal - Access - Applies to
  Users - Read - This key and subkeys
  Administrators - Full Control - This key and subkeys
  SYSTEM - Full Control - This key and subkeys
  CREATOR OWNER - Full Control - This key and subkeys
  ALL APPLICATION PACKAGES - Read - This key and subkeys

  HKEY_LOCAL_MACHINE\\SYSTEM

  Type - Allow for all
  Inherited from - None for all
  Principal - Access - Applies to
  Users - Read - This key and subkeys
  Administrators - Full Control - This key and subkeys
  SYSTEM - Full Control - This key and subkeys
  CREATOR OWNER - Full Control - Subkeys only
  ALL APPLICATION PACKAGES - Read - This key and subkeys"

  # describe "The file permissions on 'HKLM:\\SOFTWARE" do
  #   subject { command("Get-Acl -Path 'HKLM:\\SOFTWARE' | Format-List | Findstr All").stdout }
  #   it { should eq "Access : CREATOR OWNER Allow  FullControl\r\n         NT AUTHORITY\\SYSTEM Allow  FullControl\r\n         BUILTIN\\Administrators Allow  FullControl\r\n         BUILTIN\\Users Allow  ReadKey\r\n         APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES Allow  ReadKey\r\n" }
  # end

  # describe windows_registry("HKLM:\\Software\\") do
  #   it { should be_allowed('full-control', by_user: 'CREATOR OWNER') }
  #   it { should be_allowed('full-control', by_user: 'NT AUTHORITY\\SYSTEM') }
  #   it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
  #   it { should be_allowed('read', by_user: 'BUILTIN\\Users') }
  #   it { should be_allowed('read', by_user: 'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES') }
  # end

  # describe "The file permissions on 'HKLM:\\SECURITY" do
  # subject { command("Get-Acl -Path 'HKLM:\\SECURITY' | Format-List | Findstr All").stdout }
  #   it { should eq '' }
  # end

  # creator_owner_perms = command("Get-Acl -Path 'HKLM:\\SYSTEM' | Format-List | Findstr All").stdout
  # hklm_system_perms = command("Get-Acl -Path 'HKLM:\\SYSTEM' | Format-List | Findstr All").stdout

  # describe "The file permissions on 'HKLM:\\SYSTEM" do
  #   subject { hklm_system_perms }
  #   it { should eq "Access : CREATOR OWNER Allow  268435456\r\n         NT AUTHORITY\\SYSTEM Allow  268435456\r\n         NT AUTHORITY\\SYSTEM Allow  FullControl\r\n         BUILTIN\\Administrators Allow  268435456\r\n         BUILTIN\\Administrators Allow  FullControl\r\n         BUILTIN\\Users Allow  -2147483648\r\n         BUILTIN\\Users Allow  ReadKey\r\n         APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES Allow  ReadKey\r\n         APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES Allow  -2147483648\r\n" }
  # end

  # describe windows_registry("HKLM:\\SYSTEM") do
  #   it { should be_allowed('full-control', by_user: 'CREATOR OWNER') }
  #   it { should be_allowed('full-control', by_user: 'NT AUTHORITY\\SYSTEM') }
  #   it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
  #   it { should be_allowed('read', by_user: 'BUILTIN\\Users') }
  #   it { should be_allowed('read', by_user: 'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES') }
  # end

  paths = [
    "HKLM:\\\\Security",
    "HKLM:\\\\Software",
    "HKLM:\\\\System"
  ]

  paths.each do |path|
    acl_rules = json(command: "(Get-ACL -Path '#{path}').Access | ConvertTo-CSV | ConvertFrom-CSV | ConvertTo-JSON").params

    if path == "HKLM:\\\\Security"
      
    elsif path == "HKLM:\\\\Software"
      describe.one do
        acl_rules.each do |acl_rule|
          describe "The '#{path}' key\'s access rule property:" do
            subject { acl_rule }
            its(['RegistryRights']) { should cmp "FullControl" }
            its(['AccessControlType']) { should cmp "Allow" }
            its(['IdentityReference']) { should cmp "CREATOR OWNER" }
            its(['IsInherited']) { should cmp "False" }
            its(['InheritanceFlags']) { should cmp "ContainerInherit" }
            its(['PropagationFlags']) { should cmp "None" }
          end
        end
      end

      describe.one do
        acl_rules.each do |acl_rule|
          describe "The '#{path}' key\'s access rule property:" do
            subject { acl_rule }
            its(['RegistryRights']) { should cmp "FullControl" }
            its(['AccessControlType']) { should cmp "Allow" }
            its(['IdentityReference']) { should cmp "NT AUTHORITY\\SYSTEM" }
            its(['IsInherited']) { should cmp "False" }
            its(['InheritanceFlags']) { should cmp "ContainerInherit" }
            its(['PropagationFlags']) { should cmp "None" }
          end
        end
      end

      describe.one do
        acl_rules.each do |acl_rule|
          describe "The '#{path}' key\'s access rule property:" do
            subject { acl_rule }
            its(['RegistryRights']) { should cmp "FullControl" }
            its(['AccessControlType']) { should cmp "Allow" }
            its(['IdentityReference']) { should cmp "BUILTIN\\Administrators" }
            its(['IsInherited']) { should cmp "False" }
            its(['InheritanceFlags']) { should cmp "ContainerInherit" }
            its(['PropagationFlags']) { should cmp "None" }
          end
        end
      end

      describe.one do
        acl_rules.each do |acl_rule|
          describe "The '#{path}' key\'s access rule property:" do
            subject { acl_rule }
            its(['RegistryRights']) { should cmp "ReadKey" }
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
          describe "The '#{path}' key\'s access rule property:" do
            subject { acl_rule }
            its(['RegistryRights']) { should cmp "ReadKey" }
            its(['AccessControlType']) { should cmp "Allow" }
            its(['IdentityReference']) { should cmp "APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES" }
            its(['IsInherited']) { should cmp "False" }
            its(['InheritanceFlags']) { should cmp "ContainerInherit" }
            its(['PropagationFlags']) { should cmp "None" }
          end
        end
      end

    elsif path == "HKLM:\\\\System"
      describe.one do
        acl_rules.each do |acl_rule|
          describe "The '#{path}' key\'s access rule property:" do
            subject { acl_rule }
            its(['RegistryRights']) { should cmp "268435456" }
            its(['AccessControlType']) { should cmp "Allow" }
            its(['IdentityReference']) { should cmp "CREATOR OWNER" }
            its(['IsInherited']) { should cmp "False" }
            its(['InheritanceFlags']) { should cmp "ContainerInherit" }
            its(['PropagationFlags']) { should cmp "InheritOnly" }
          end
        end
      end

      describe.one do
        acl_rules.each do |acl_rule|
          describe "The '#{path}' key\'s access rule property:" do
            subject { acl_rule }
            its(['RegistryRights']) { should cmp "ReadKey" }
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
          describe "The '#{path}' key\'s access rule property:" do
            subject { acl_rule }
            its(['RegistryRights']) { should cmp "268435456" }
            its(['AccessControlType']) { should cmp "Allow" }
            its(['IdentityReference']) { should cmp "NT AUTHORITY\\SYSTEM" }
            its(['IsInherited']) { should cmp "False" }
            its(['InheritanceFlags']) { should cmp "ContainerInherit" }
            its(['PropagationFlags']) { should cmp "InheritOnly" }
          end
        end
      end

      describe.one do
        acl_rules.each do |acl_rule|
          describe "The '#{path}' key\'s access rule property:" do
            subject { acl_rule }
            its(['RegistryRights']) { should cmp "FullControl" }
            its(['AccessControlType']) { should cmp "Allow" }
            its(['IdentityReference']) { should cmp "NT AUTHORITY\\SYSTEM" }
            its(['IsInherited']) { should cmp "False" }
            its(['InheritanceFlags']) { should cmp "None" }
            its(['PropagationFlags']) { should cmp "None" }
          end
        end
      end

      describe.one do
        acl_rules.each do |acl_rule|
          describe "The '#{path}' key\'s access rule property:" do
            subject { acl_rule }
            its(['RegistryRights']) { should cmp "268435456" }
            its(['AccessControlType']) { should cmp "Allow" }
            its(['IdentityReference']) { should cmp "BUILTIN\\Administrators" }
            its(['IsInherited']) { should cmp "False" }
            its(['InheritanceFlags']) { should cmp "ContainerInherit" }
            its(['PropagationFlags']) { should cmp "InheritOnly" }
          end
        end
      end

      describe.one do
        acl_rules.each do |acl_rule|
          describe "The '#{path}' key\'s access rule property:" do
            subject { acl_rule }
            its(['RegistryRights']) { should cmp "FullControl" }
            its(['AccessControlType']) { should cmp "Allow" }
            its(['IdentityReference']) { should cmp "BUILTIN\\Administrators" }
            its(['IsInherited']) { should cmp "False" }
            its(['InheritanceFlags']) { should cmp "None" }
            its(['PropagationFlags']) { should cmp "None" }
          end
        end
      end

      describe.one do
        acl_rules.each do |acl_rule|
          describe "The '#{path}' key\'s access rule property:" do
            subject { acl_rule }
            its(['RegistryRights']) { should cmp "ReadKey" }
            its(['AccessControlType']) { should cmp "Allow" }
            its(['IdentityReference']) { should cmp "APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES" }
            its(['IsInherited']) { should cmp "False" }
            its(['InheritanceFlags']) { should cmp "None" }
            its(['PropagationFlags']) { should cmp "None" }
          end
        end
      end

      describe.one do
        acl_rules.each do |acl_rule|
          describe "The '#{path}' key\'s access rule property:" do
            subject { acl_rule }
            its(['RegistryRights']) { should cmp "-2147483648" }
            its(['AccessControlType']) { should cmp "Allow" }
            its(['IdentityReference']) { should cmp "APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES" }
            its(['IsInherited']) { should cmp "False" }
            its(['InheritanceFlags']) { should cmp "ContainerInherit" }
            its(['PropagationFlags']) { should cmp "InheritOnly" }
          end
        end
      end
    end

  end
end  
   