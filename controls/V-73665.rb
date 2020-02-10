control 'V-73665' do
  title 'Anonymous SID/Name translation must not be allowed.'
  desc  "Allowing anonymous SID/Name translation can provide sensitive
  information for accessing a system. Only authorized users must be able to
  perform such translations."
  impact 0.7
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-73665'
  tag "rid": 'SV-88329r1_rule'
  tag "stig_id": 'WN16-SO-000250'
  tag "fix_id": 'F-80115r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  desc "check", "Verify the effective setting in Local Group Policy Editor.

  Run gpedit.msc.

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> Security Options.

  If the value for Network access: Allow anonymous SID/Name translation is
  not set to Disabled, this is a finding."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  Network access: Allow anonymous SID/Name translation to Disabled."
  describe security_policy do
    its('LSAAnonymousNameLookup') { should eq 0 }
  end
end
