control 'V-73245' do
  title "Servers must have a host-based intrusion detection or prevention
  system."
  desc "A properly configured Host-based Intrusion Detection System (HIDS) or
  Host-based Intrusion Prevention System (HIPS) provides another level of defense
  against unauthorized access to critical servers. With proper configuration and
  logging enabled, such a system can stop and/or alert for many attempts to gain
  unauthorized access to resources."
  impact 0.5
  tag "gtitle": 'SRG-OS-000480-GPOS-00227'
  tag "gid": 'V-73245'
  tag "rid": 'SV-87897r1_rule'
  tag "stig_id": 'WN16-00-000140'
  tag "fix_id": 'F-79689r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "Determine whether there is a HIDS or HIPS on each server.

  If the HIPS component of HBSS is installed and active on the host and the
  alerts of blocked activity are being logged and monitored, this meets the
  requirement.

  A HIDS device is not required on a system that has the role as the Network
  Intrusion Device (NID). However, this exception needs to be documented with the
  ISSO.

  If a HIDS is not installed on the system, this is a finding."
  tag "fix": 'Install a HIDS or HIPS on each server.'
  describe 'A manual review is required to determine whether this server has a host-based Intrusion Detection System installed' do
    skip 'A manual review is required to determine whether this server has a host-based Intrusion Detection System installed'
  end
end
