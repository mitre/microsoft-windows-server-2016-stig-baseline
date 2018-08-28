control "V-73305" do
  title "FTP servers must be configured to prevent access to the system drive."
  desc  "The FTP service allows remote users to access shared files and
  directories that could provide access to system resources and compromise the
  system, especially if the user can gain access to the root directory of the
  boot drive."
  if (is_ftp_installed == 'False' || is_ftp_installed == '')
    impact 0.0
  else
    impact 0.5
  end
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73305"
  tag "rid": "SV-87957r1_rule"
  tag "stig_id": "WN16-00-000440"
  tag "fix_id": "F-79747r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If FTP is not installed on the system, this is NA.

  Open \"Internet Information Services (IIS) Manager\".

  Select \"Sites\" under the server name.

  For any sites with a Binding that lists FTP, right-click the site and select
  \"Explore\".

  If the site is not defined to a specific folder for shared FTP resources, this
  is a finding.

  If the site includes any system areas such as root of the drive, Program Files,
  or Windows directories, this is a finding."
  tag "fix": "Configure the FTP sites to allow access only to specific FTP
  shared resources. Do not allow access to other areas of the system."
  describe 'File Transfer Protocol (FTP) servers must be configured to prevent
  anonymous logons' do
    skip "is a manual check"
  end
end

