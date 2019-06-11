control 'V-73277' do
  title 'The roles and features required by the system must be documented.'
  desc  "Unnecessary roles and features increase the attack surface of a
  system. Limiting roles and features of a system to only those necessary reduces
  this potential. The standard installation option (previously called Server
  Core) further reduces this when selected at installation."
  impact 0.5
  tag "gtitle": 'SRG-OS-000095-GPOS-00049'
  tag "gid": 'V-73277'
  tag "rid": 'SV-87929r1_rule'
  tag "stig_id": 'WN16-00-000300'
  tag "fix_id": 'F-79721r1_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "Required roles and features will vary based on the function of
  the individual system.

  Roles and features specifically required to be disabled per the STIG are
  identified in separate requirements.

  If the organization has not documented the roles and features required for the
  system(s), this is a finding.

  The PowerShell command Get-WindowsFeature will list all roles and features
  with an Install State."
  tag "fix": "Document the roles and features required for the system to
  operate. Uninstall any that are not required."
  describe 'A manual review is required to verify that the roles and features required by the system are documented' do
    skip 'A manual review is required to verify that the roles and features required by the system are documented'
  end
end
