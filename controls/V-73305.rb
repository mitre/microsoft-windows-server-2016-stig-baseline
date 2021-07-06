control 'V-73305' do
  title 'FTP servers must be configured to prevent access to the system drive.'
  desc  "The FTP service allows remote users to access shared files and
  directories that could provide access to system resources and compromise the
  system, especially if the user can gain access to the root directory of the
  boot drive."
  impact 0.5
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-73305'
  tag "rid": 'SV-87957r1_rule'
  tag "stig_id": 'WN16-00-000440'
  tag "fix_id": 'F-79747r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  desc "check", "If FTP is not installed on the system, this is NA.

  Open Internet Information Services (IIS) Manager.

  Select Sites under the server name.

  For any sites with a Binding that lists FTP, right-click the site and select
  Explore.

  If the site is not defined to a specific folder for shared FTP resources, this
  is a finding.

  If the site includes any system areas such as root of the drive, Program Files,
  or Windows directories, this is a finding."
  desc "fix", "Configure the FTP sites to allow access only to specific FTP
  shared resources. Do not allow access to other areas of the system."
  is_ftp_installed = command('Get-WindowsFeature Web-Ftp-Server | Select -Expand Installed').stdout.strip

  if is_ftp_installed == "False"
    describe windows_feature('Web-Ftp-Server') do
      it { should_not be_installed }
    end
  end
  if is_ftp_installed == "True"
    describe 'A manual review is required to ensure File Transfer Protocol (FTP) servers are configured to prevent anonymous logons' do
      skip 'A manual review is required to ensure File Transfer Protocol (FTP) servers are configured to prevent anonymous logos'
    end
  end

end
