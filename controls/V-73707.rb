control 'V-73707' do
  title "User Account Control approval mode for the built-in Administrator must
  be enabled."
  desc "User Account Control (UAC) is a security mechanism for limiting the
  elevation of privileges, including administrative accounts, unless authorized.
  This setting configures the built-in Administrator account so that it runs in
  Admin Approval Mode.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000373-GPOS-00157'
  tag "satisfies": ['SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00156']
  tag "gid": 'V-73707'
  tag "rid": 'SV-88371r1_rule'
  tag "stig_id": 'WN16-SO-000460'
  tag "fix_id": 'F-80157r1_fix'
  tag "cci": ['CCI-002038']
  tag "nist": ['IA-11', 'Rev_4']
  tag "documentable": false
  tag "check": "UAC requirements are NA for Server Core installations (this is
  the default installation option for Windows Server 2016 versus Server with
  Desktop Experience) as well as Nano Server.

  If the following registry value does not exist or is not configured as
  specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: FilterAdministratorToken

  Value Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >> User
  Account Control: Admin Approval Mode for the Built-in Administrator account
  to Enabled."
  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('ServerCore', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Mgmt', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Shell', :dword, 1)
    impact 0.0
    desc 'This system is a Server Core Installation, therefore this control is not applicable'
  else
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
      it { should have_property 'FilterAdministratorToken' }
      its('FilterAdministratorToken') { should cmp 1 }
    end
  end
end
