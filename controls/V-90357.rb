control 'V-90357' do
  title "Windows 2016 systems must have Unified Extensible Firmware Interface (UEFI) 
  firmware and be configured to run in UEFI mode, not Legacy BIOS."
  desc "UEFI provides additional security features in comparison to legacy BIOS 
  firmware, including Secure Boot. UEFI is required to support additional security 
  features in Windows Server 2016, including Virtualization Based Security and 
  Credential Guard. Systems with UEFI that are operating in Legacy BIOS mode 
  will not support these security features."
  impact 0.3
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-90357'
  tag "rid": 'SV-101007r2_rule'
  tag "stig_id": 'WN16-00-000480'
  tag "fix_id": 'tbd'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b']
  tag "documentable": false
  desc "check" "Some older systems may not have UEFI firmware. This is currently a CAT III; 
  it will be raised in severity at a future date when broad support of Windows hardware and 
  firmware requirements are expected to be met. Devices that have UEFI firmware must run in UEFI mode.
  
  Verify the system firmware is configured to run in UEFI mode, not Legacy BIOS.

  Run System Information

  Under System Summary, if BIOS Mode does not display UEFI, this is finding.
  "
  
  desc "fix" "Configure UEFI firmware to run in UEFI mode, not Legacy BIOS mode."
  
  describe "This is enabled outside of the OS and needs to be verified manually" do
    skip "Verify that UEFI BIOS mode is Enabled"
  end

end