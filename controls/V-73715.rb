control "V-73715" do
  title "User Account Control must be configured to detect application
  installations and prompt for elevation."
  desc  "User Account Control (UAC) is a security mechanism for limiting the
  elevation of privileges, including administrative accounts, unless authorized.
  This setting requires Windows to respond to application installation requests
  by prompting for credentials."
  if (registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('ServerCore', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Mgmt', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Shell', :dword, 1))
    impact 0.0
  else
    impact 0.5
  end
  tag "gtitle": "SRG-OS-000134-GPOS-00068"
  tag "gid": "V-73715"
  tag "rid": "SV-88379r1_rule"
  tag "stig_id": "WN16-SO-000500"
  tag "fix_id": "F-80165r1_fix"
  tag "cci": ["CCI-001084"]
  tag "nist": ["SC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "UAC requirements are NA for Server Core installations (this is
  the default installation option for Windows Server 2016 versus Server with
  Desktop Experience) as well as Nano Server.

  If the following registry value does not exist or is not configured as
  specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: EnableInstallerDetection

  Value Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >> \"User
  Account Control: Detect application installations and prompt for elevation\" to
  \"Enabled\"."
  if (registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('ServerCore', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Mgmt', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Shell', :dword, 1))
    describe "This system is a Server Core Installation, control is NA" do
      skip "This system is a Server Core Installation control is NA"
    end
  end
  else
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
      it { should have_property "EnableInstallerDetection" }
      its("EnableInstallerDetection") { should cmp == 1 }
    end
  end
end

