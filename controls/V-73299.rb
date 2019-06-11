control 'V-73299' do
  title 'The Server Message Block (SMB) v1 protocol must be uninstalled.'
  desc  "SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB.
  MD5 is known to be vulnerable to a number of attacks such as collision and
  preimage attacks and is not FIPS compliant."
  impact 0.5
  tag "gtitle": 'SRG-OS-000095-GPOS-00049'
  tag "gid": 'V-73299'
  tag "rid": 'SV-87951r2_rule'
  tag "stig_id": 'WN16-00-000410'
  tag "fix_id": 'F-84915r1_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7', 'Rev_4']
  tag "documentable": false
  tag "check": "Different methods are available to disable SMBv1 on Windows
  2016.  This is the preferred method, however if V-78123 and V-78125 are
  configured, this is NA.

  Open Windows PowerShell with elevated privileges (run as administrator).

  Enter Get-WindowsFeature -Name FS-SMB1.

  If Installed State is Installed, this is a finding.

  An Installed State of Available or Removed is not a finding."
  tag "fix": "Uninstall the SMBv1 protocol.

  Open Windows PowerShell with elevated privileges (run as administrator).

  Enter Uninstall-WindowsFeature -Name FS-SMB1 -Restart.
  (Omit the Restart parameter if an immediate restart of the system cannot be
  done.)

  Alternately:

  Start Server Manager.

  Select the server with the feature.

  Scroll down to ROLES AND FEATURES in the right pane.

  Select Remove Roles and Features from the drop-down TASKS list.

  Select the appropriate server on the Server Selection page and click
  Next.

  Deselect SMB 1.0/CIFS File Sharing Support on the Features page.

  Click Next and Remove as prompted."
  if registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters').has_property_value?('SMB1', :dword, 0) && registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10').has_property_value?('Start', :dword, 4)
    impact 0.0
    desc 'This control is not applicable, as controls V-78123 and V-78125 are configured'
  else
    describe windows_feature('FS-SMB1') do
      it { should_not be_installed }
    end
  end
end
