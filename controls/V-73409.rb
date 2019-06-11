control 'V-73409' do
  title "Permissions for the System event log must prevent access by
  non-privileged accounts."
  desc "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks. Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised. The
  System event log may be susceptible to tampering if proper permissions are not
  applied.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000057-GPOS-00027'
  tag "satisfies": ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028',
                    'SRG-OS-000059-GPOS-00029']
  tag "gid": 'V-73409'
  tag "rid": 'SV-88061r1_rule'
  tag "stig_id": 'WN16-AU-000050'
  tag "fix_id": 'F-79851r1_fix'
  tag "cci": ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag "nist": ['AU-9', 'Rev_4']
  tag "documentable": false
  tag "check": "Navigate to the System event log file.

  The default location is the %SystemRoot%\\System32\\winevt\\Logs folder.
  However, the logs may have been moved to another folder.

  If the permissions for the System.evtx file are not as restrictive as the
  default permissions listed below, this is a finding.

  Eventlog - Full Control
  SYSTEM - Full Control
  Administrators - Full Control"
  tag "fix": "Configure the permissions on the System event log file
  (System.evtx) to prevent access by non-privileged accounts. The default
  permissions listed below satisfy this requirement:

  Eventlog - Full Control
  SYSTEM - Full Control
  Administrators - Full Control

  The default location is the %SystemRoot%\\ System32\\winevt\\Logs folder.

  If the location of the logs has been changed, when adding Eventlog to the
  permissions, it must be entered as NT Service\\Eventlog."
  system_root = command('$env:SystemRoot').stdout.strip

  describe file("#{system_root}\\SYSTEM32\\WINEVT\\LOGS\\System.evtx") do
    it { should be_allowed('full-control', by_user: 'NT SERVICE\\EventLog') }
    it { should be_allowed('full-control', by_user: 'NT AUTHORITY\\SYSTEM') }
    it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
  end
end
