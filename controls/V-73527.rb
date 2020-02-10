control 'V-73527' do
  title 'Downloading print driver packages over HTTP must be prevented.'
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature. Turning off this
  capability will prevent potentially sensitive information from being sent
  outside the enterprise and will prevent uncontrolled updates to the system.

  This setting prevents the computer from downloading print driver packages
  over HTTP.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000095-GPOS-00049'
  tag "gid": 'V-73527'
  tag "rid": 'SV-88179r1_rule'
  tag "stig_id": 'WN16-CC-000160'
  tag "fix_id": 'F-79969r1_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  desc "check", "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\

  Value Name: DisableWebPnPDownload

  Type: REG_DWORD
  Value: 0x00000001 (1)"
  desc "fix", "Configure the policy value for Computer Configuration >>
  Administrative Templates >> System >> Internet Communication Management >>
  Internet Communication settings >> Turn off downloading of print drivers over
  HTTP to Enabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers') do
    it { should have_property 'DisableWebPnPDownload' }
    its('DisableWebPnPDownload') { should cmp 1 }
  end
end
