control 'V-102623' do
  title "The Windows Explorer Preview pane must be disabled for Windows Server 2016."
  desc " A known vulnerability in Windows could allow the execution of malicious 
  code by either opening a compromised document or viewing it in the Windows Preview pane.

  Organizations must disable the Windows Preview pane and Windows Detail pane."
  impact 0.5
  tag "gtitle": 'WN16-CC-000421'
  tag "gid": 'V-102623'
  tag "rid": 'SV-101881r2_rule'
  tag "stig_id": 'WN16-CC-000421'
  tag "fix_id": 'tbd'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b']
  tag "documentable": false
  desc "check" "If the following registry values do not exist or are not configured as specified, this is a finding:

    Registry Hive: HKEY_CURRENT_USER
    Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer
    Value Name: NoPreviewPane
    Value Type: REG_DWORD
    Value: 1

    Registry Hive: HKEY_CURRENT_USER
    Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer
    Value Name: NoReadingPane
    Value Type: REG_DWORD
    Value: 1"
  
  desc "fix" "Ensure the following settings are configured for Windows Server 2016 locally or applied through group policy. 

  Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> File Explorer >> Explorer Frame Pane Turn off Preview Pane to Enabled.

  Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> File Explorer >> Explorer Frame Pane Turn on or off details pane" to \"Enabled\" and \"Configure details pane\" to \"Always hide\""

  describe registry_key('HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('NoPreviewPane') { should eq 1 }
  end
  describe registry_key('HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('NoReadingPane') { should eq 1 }
  end
  
end