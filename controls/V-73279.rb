control 'V-73279' do
  title 'A host-based firewall must be installed and enabled on the system.'
  desc  "A firewall provides a line of defense against attack, allowing or
  blocking inbound and outbound connections based on a set of rules."
  impact 0.5
  tag "gtitle": 'SRG-OS-000480-GPOS-00231'
  tag "gid": 'V-73279'
  tag "rid": 'SV-87931r1_rule'
  tag "stig_id": 'WN16-00-000310'
  tag "fix_id": 'F-79723r1_fix'
  tag "cci": ['CCI-000366', 'CCI-002080']
  tag "nist": ['CM-6 b', 'CA-3 (5)', 'Rev_4']
  tag "documentable": false
  desc "check", "Determine if a host-based firewall is installed and enabled on
  the system.

  If a host-based firewall is not installed and enabled on the system, this is a
  finding.

  The configuration requirements will be determined by the applicable firewall
  STIG."
  desc "fix", 'Install and enable a host-based firewall on the system.'
  describe 'A manual review is required to verify that a host-based firewall is installed and enabled on this system' do
    skip 'A manual review is required to verify that a host-based firewall is installed and enabled on this system'
  end
end
