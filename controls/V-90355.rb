control 'V-90355' do
  title "Secure Boot must be enabled on Windows Server 2016 systems."
  desc "Secure Boot is a standard that ensures systems boot only to a 
  trusted operating system. Secure Boot is required to support additional 
  security features in Windows Server 2016, including Virtualization 
  Based Security and Credential Guard. If Secure Boot is turned off, 
  these security features will not function."
  impact 0.3
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-90355'
  tag "rid": 'SV-101005r2_rule'
  tag "stig_id": 'WN16-00-000470'
  tag "fix_id": 'tbd'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b']
  tag "documentable": false
  desc "check" "Some older systems may not have UEFI firmware. This is currently a CAT III; 
  it will be raised in severity at a future date when broad support of Windows hardware 
  and firmware requirements are expected to be met. Devices that have UEFI firmware 
  must have Secure Boot enabled. 
  
  Run System Information

  Under System Summary, if Secure Boot State does not display On, this is finding.
  "
  
  desc "fix" "Enable Secure Boot in the system firmware."
  
  describe "This is enabled outside of the OS and needs to be verified manually" do
    skip "Verify that Secure Boot is Enabled"
  end

end