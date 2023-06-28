control 'V-73369' do
  title "Permissions on the Active Directory data files must only allow System
  and Administrators access."
  desc  "Improper access permissions for directory data-related files could
  allow unauthorized users to read, modify, or delete directory data or audit
  trails."
  impact 0.7
  tag "gtitle": 'SRG-OS-000324-GPOS-00125'
  tag "gid": 'V-73369'
  tag "rid": 'SV-88021r1_rule'
  tag "stig_id": 'WN16-DC-000070'
  tag "fix_id": 'F-79811r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  desc "check", "This applies to domain controllers. It is NA for other systems.

  Run Regedit.

  Navigate to
  HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters.

  Note the directory locations in the values for:

  Database log files path
  DSA Database file

  By default, they will be \\Windows\\NTDS.

  If the locations are different, the following will need to be run for each.

  Open Command Prompt (Admin).

  Navigate to the NTDS directory (\\Windows\\NTDS by default).

  Run icacls *.*.

  If the permissions on each file are not as restrictive as the following, this
  is a finding.

  NT AUTHORITY\\SYSTEM:(I)(F)
  BUILTIN\\Administrators:(I)(F)

  (I) - permission inherited from parent container
  (F) - full access"
  desc "fix", "Maintain the permissions on NTDS database and log files as
  follows:

  NT AUTHORITY\\SYSTEM:(I)(F)
  BUILTIN\\Administrators:(I)(F)

  (I) - permission inherited from parent container
  (F) - full access"

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    default_path = "\\Windows\\NTDS"
    reg_params = registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters')
    dsa_db_file_path = reg_params['DSA Database file'].split(":")[1]
    db_log_files_path = reg_params['Database log files path'].split(":")[1]
    if !dsa_db_file_path.start_with?(default_path) || !db_log_files_path.start_with?(default_path)
      acl_rules = []
      if !dsa_db_file_path.start_with?(default_path)
        acl_rules = json(command: "(Get-ACL -Path '#{reg_params['DSA Database file']}') | Select -Property PSChildName -ExpandProperty Access | ConvertTo-CSV | ConvertFrom-CSV | ConvertTo-JSON").params
      end
      if !db_log_files_path.start_with?(default_path)
        acl_rules.push(*json(command: "(Get-ACL -Path '#{reg_params['Database log files path']}\\\*.\*') | Select -Property PSChildName -ExpandProperty Access | ConvertTo-CSV | ConvertFrom-CSV | ConvertTo-JSON").params)
      end
      acl_rules.each do |acl_rule|
        describe "The #{acl_rule['PSChildName']} file\'s access rule property" do
          subject { acl_rule }
          its(['FileSystemRights']) { should cmp "FullControl" }
          its(['AccessControlType']) { should cmp "Allow" }
          its(['IsInherited']) { should cmp "True" }
          its(['InheritanceFlags']) { should cmp "None" }
          its(['PropagationFlags']) { should cmp "None" }
        end
        describe.one do
          describe "The #{acl_rule['PSChildName']} file\'s access rule property" do
            subject { acl_rule }
            its(['IdentityReference']) { should cmp "NT AUTHORITY\\SYSTEM" }
          end
          describe "The #{acl_rule['PSChildName']} file\'s access rule property" do
            subject { acl_rule }
            its(['IdentityReference']) { should cmp "BUILTIN\\Administrators" }
          end
        end
      end
    else
      describe "Database log files path" do
        subject { db_log_files_path }
        it { should cmp default_path }
      end
      describe "DSA Database file" do
        subject { dsa_db_file_path }
        it { should start_with default_path}
      end
    end
  else
    impact 0.0
    describe 'This system is not a domain controller, therefore this control is not applicable.' do
      skip 'This system is not a domain controller, therefore this control is not applicable.'
    end
  end
end
 