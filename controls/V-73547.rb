control 'V-73547' do
  title "The default AutoRun behavior must be configured to prevent AutoRun
  commands."
  desc "Allowing AutoRun commands to execute may introduce malicious code to a
  system. Configuring this setting prevents AutoRun commands from executing."
  impact 0.7
  tag "gtitle": 'SRG-OS-000368-GPOS-00154'
  tag "gid": 'V-73547'
  tag "rid": 'SV-88211r1_rule'
  tag "stig_id": 'WN16-CC-000260'
  tag "fix_id": 'F-79997r1_fix'
  tag "cci": ['CCI-001764']
  tag "nist": ['CM-7 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

  Value Name: NoAutorun

  Type: REG_DWORD
  Value: 0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> Windows Components >> AutoPlay Policies >> Set
  the default behavior for AutoRun to Enabled with Do not execute any
  autorun commands selected."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoAutorun' }
    its('NoAutorun') { should cmp 1 }
  end
end
