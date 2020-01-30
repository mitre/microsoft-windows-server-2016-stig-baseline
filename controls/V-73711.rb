control 'V-73711' do
  title "User Account Control must, at a minimum, prompt administrators for
  consent on the secure desktop."
  desc "User Account Control (UAC) is a security mechanism for limiting the
  elevation of privileges, including administrative accounts, unless authorized.
  This setting configures the elevation requirements for logged-on administrators
  to complete a task that requires raised privileges."
  impact 0.5
  tag "gtitle": 'SRG-OS-000134-GPOS-00068'
  tag "gid": 'V-73711'
  tag "rid": 'SV-88375r1_rule'
  tag "stig_id": 'WN16-SO-000480'
  tag "fix_id": 'F-80161r1_fix'
  tag "cci": ['CCI-001084']
  tag "nist": ['SC-3', 'Rev_4']
  tag "documentable": false
  desc "check", "UAC requirements are NA for Server Core installations (this is
  default installation option for Windows Server 2016 versus Server with Desktop
  Experience) as well as Nano Server.

  If the following registry value does not exist or is not configured as
  specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: ConsentPromptBehaviorAdmin

  Value Type: REG_DWORD
  Value: 0x00000002 (2) (Prompt for consent on the secure desktop)
  0x00000001 (1) (Prompt for credentials on the secure desktop)"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >> User
  Account Control: Behavior of the elevation prompt for administrators in Admin
  Approval Mode to Prompt for consent on the secure desktop.

  The more secure option for this setting, Prompt for credentials on the secure
  desktop, would also be acceptable."
  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('ServerCore', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Mgmt', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Shell', :dword, 1)
    impact 0.0
    desc 'This system is a Server Core Installation, therefore this control is not applicable'
  else
    describe.one do
      describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
        it { should have_property 'ConsentPromptBehaviorAdmin' }
        its('ConsentPromptBehaviorAdmin') { should cmp 2 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
        it { should have_property 'ConsentPromptBehaviorAdmin' }
        its('ConsentPromptBehaviorAdmin') { should cmp 1 }
      end
    end
  end
end
