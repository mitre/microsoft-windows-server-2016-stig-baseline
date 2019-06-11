control 'V-73579' do
  title 'Basic authentication for RSS feeds over HTTP must not be used.'
  desc  "Basic authentication uses plain-text passwords that could be used to
  compromise a system. Disabling Basic authentication will reduce this potential."
  impact 0.5
  tag "gtitle": 'SRG-OS-000095-GPOS-00049'
  tag "gid": 'V-73579'
  tag "rid": 'SV-88243r1_rule'
  tag "stig_id": 'WN16-CC-000430'
  tag "fix_id": 'F-80029r1_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "The default behavior is for the Windows RSS platform to not use
  Basic authentication over HTTP connections.

  If the registry value name below does not exist, this is not a finding.

  If it exists and is configured with a value of 0, this is not a finding.

  If it exists and is configured with a value of 1, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

  Value Name: AllowBasicAuthInClear

  Value Type: REG_DWORD
  Value: 0x00000000 (0) (or if the Value Name does not exist)"
  tag "fix": "The default behavior is for the Windows RSS platform to not use
  Basic authentication over HTTP connections.

  If this needs to be corrected, configure the policy value for Computer
  Configuration >> Administrative Templates >> Windows Components >> RSS Feeds >>
  Turn on Basic feed authentication over HTTP to Not Configured or
  Disabled."
  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds') do
      it { should_not have_property 'AllowBasicAuthInClear' }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds') do
      its('AllowBasicAuthInClear') { should cmp 0 }
    end
  end
end
