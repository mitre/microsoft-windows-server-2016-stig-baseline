control "V-73265" do
  title "System files must be monitored for unauthorized changes."
  desc  "Monitoring system files for changes against a baseline on a regular
  basis may help detect the possible introduction of malicious code on a system."
  impact 0.5
  tag "gtitle": "SRG-OS-000363-GPOS-00150"
  tag "gid": "V-73265"
  tag "rid": "SV-87917r1_rule"
  tag "stig_id": "WN16-00-000240"
  tag "fix_id": "F-79709r1_fix"
  tag "cci": ["CCI-001744"]
  tag "nist": ["CM-3 (5)", "Rev_4"]
  tag "documentable": false
  tag "check": "Determine whether the system is monitored for unauthorized
  changes to system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a
  baseline on a weekly basis.

  If system files are not monitored for unauthorized changes, this is a finding.

  A properly configured HBSS Policy Auditor 5.2 or later File Integrity Monitor
  (FIM) module will meet the requirement for file integrity checking. The Asset
  module within HBSS does not meet this requirement."
  tag "fix": "Monitor the system for unauthorized changes to system files
  (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a baseline on a weekly
  basis. This can be done with the use of various monitoring tools."
  describe "System files must be monitored for unauthorized changes" do
    skip "is a manual check"
  end
end

