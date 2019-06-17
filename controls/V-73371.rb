control 'V-73371' do
  title "The Active Directory SYSVOL directory must have the proper access
  control permissions."
  desc "Improper access permissions for directory data files could allow
  unauthorized users to read, modify, or delete directory data.

      The SYSVOL directory contains public files (to the domain) such as policies
  and logon scripts. Data in shared subdirectories are replicated to all domain
  controllers in a domain.
  "
  impact 0.7
  tag "gtitle": 'SRG-OS-000324-GPOS-00125'
  tag "gid": 'V-73371'
  tag "rid": 'SV-88023r1_rule'
  tag "stig_id": 'WN16-DC-000080'
  tag "fix_id": 'F-79813r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "This applies to domain controllers. It is NA for other systems.

  Open a command prompt.

  Run net share.

  Make note of the directory location of the SYSVOL share.

  By default, this will be \\Windows\\SYSVOL\\sysvol. For this requirement,
  permissions will be verified at the first SYSVOL directory level.

  If any standard user accounts or groups have greater than \"Read & execute\"
  permissions, this is a finding.

  The default permissions noted below meet this requirement.

  Open Command Prompt.

  Run \"icacls c:\\Windows\\SYSVOL\".

  The following results should be displayed:

  NT AUTHORITY\\Authenticated Users:(RX)
  NT AUTHORITY\\Authenticated Users:(OI)(CI)(IO)(GR,GE)
  BUILTIN\\Server Operators:(RX)
  BUILTIN\\Server Operators:(OI)(CI)(IO)(GR,GE)
  BUILTIN\\Administrators:(M,WDAC,WO)
  BUILTIN\\Administrators:(OI)(CI)(IO)(F)
  NT AUTHORITY\\SYSTEM:(F)
  NT AUTHORITY\\SYSTEM:(OI)(CI)(IO)(F)
  BUILTIN\\Administrators:(M,WDAC,WO)
  CREATOR OWNER:(OI)(CI)(IO)(F)

  (RX) - Read & execute

  Run icacls /help to view definitions of other permission codes.

  Alternately, open File Explorer.

  Navigate to \\Windows\\SYSVOL (or the directory noted previously if different).

  Right-click the directory and select properties.

  Select the Security tab and click Advanced.

  Default permissions:

  C:\\Windows\\SYSVOL
  Type - \"Allow\" for all
  Inherited from - \"None\" for all

  Principal - Access - Applies to

  Authenticated Users - Read & execute - This folder, subfolder, and files
  Server Operators - Read & execute- This folder, subfolder, and files
  Administrators - Special - This folder only (Special = Basic Permissions: all
  selected except Full control)
  CREATOR OWNER - Full control - Subfolders and files only
  Administrators - Full control - Subfolders and files only
  SYSTEM - Full control - This folder, subfolders, and files"
  tag "fix": "Maintain the permissions on the SYSVOL directory. Do not allow
  greater than Read & execute permissions for standard user accounts or
  groups. The defaults below meet this requirement.

  C:\\Windows\\SYSVOL
  Type - Allow for all
  Inherited from - None for all

  Principal - Access - Applies to

  Authenticated Users - Read & execute - This folder, subfolder, and files
  Server Operators - Read & execute- This folder, subfolder, and files
  Administrators - Special - This folder only (Special = Basic Permissions: all
  selected except Full control)
  CREATOR OWNER - Full control - Subfolders and files only
  Administrators - Full control - Subfolders and files only
  SYSTEM - Full control - This folder, subfolders, and files"

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

  if domain_role == '4' || domain_role == '5'
    describe file('C:\\Windows\\SYSVOL\\sysvol') do
      it { should be_allowed('full-control', by_user: 'CREATOR OWNER') }
      it { should be_allowed('read', by_user: 'NT AUTHORITY\\Authenticated Users Allow') }
      it { should be_allowed('full-control', by_user: 'NT AUTHORITY\\SYSTEM') }
      it { should be_allowed('read', by_user: 'BUILTIN\\Administrators') }
      it { should be_allowed('read', by_user: 'BUILTIN\\Server Operators') }
    end
  end

  if domain_role != '4' && domain_role != '5'
    impact 0.0
    desc 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end
