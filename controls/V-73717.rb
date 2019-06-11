control 'V-73717' do
  title "User Account Control must only elevate UIAccess applications that are
  installed in secure locations."
  desc "User Account Control (UAC) is a security mechanism for limiting the
  elevation of privileges, including administrative accounts, unless authorized.
  This setting configures Windows to only allow applications installed in a
  secure location on the file system, such as the Program Files or the
  Windows\\System32 folders, to run with elevated privileges."
  impact 0.5
  tag "gtitle": 'SRG-OS-000134-GPOS-00068'
  tag "gid": 'V-73717'
  tag "rid": 'SV-88381r1_rule'
  tag "stig_id": 'WN16-SO-000510'
  tag "fix_id": 'F-80167r1_fix'
  tag "cci": ['CCI-001084']
  tag "nist": ['SC-3', 'Rev_4']
  tag "documentable": false
  tag "check": "UAC requirements are NA for Server Core installations (this is
  the default installation option for Windows Server 2016 versus Server with
  Desktop Experience) as well as Nano Server.

  If the following registry value does not exist or is not configured as
  specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: EnableSecureUIAPaths

  Value Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >> User
  Account Control: Only elevate UIAccess applications that are installed in
  secure locations to Enabled."
  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('ServerCore', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Mgmt', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Shell', :dword, 1)
    impact 0.0
    desc 'This system is a Server Core Installation, therefore this control is not applicable'
  else
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
      it { should have_property 'EnableSecureUIAPaths' }
      its('EnableSecureUIAPaths') { should cmp 1 }
    end
  end
end
