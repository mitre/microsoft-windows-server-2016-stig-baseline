control 'V-73505' do
  title "Windows Server 2016 must be configured to ignore NetBIOS name release
  requests except from WINS servers."
  desc "Configuring the system to ignore name release requests, except from
  WINS servers, prevents a denial of service (DoS) attack. The DoS consists of
  sending a NetBIOS name release request to the server for each entry in the
  server's cache, causing a response delay in the normal operation of the
  server's WINS resolution capability."
  impact 0.3
  tag "gtitle": 'SRG-OS-000420-GPOS-00186'
  tag "gid": 'V-73505'
  tag "rid": 'SV-88157r1_rule'
  tag "stig_id": 'WN16-CC-000070'
  tag "fix_id": 'F-79947r1_fix'
  tag "cci": ['CCI-002385']
  tag "nist": ['SC-5', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters\\

  Value Name:  NoNameReleaseOnDemand

  Value Type:  REG_DWORD
  Value:  0x00000001 (1)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> MSS (Legacy) >> \"MSS: (NoNameReleaseOnDemand)
  Allow the computer to ignore NetBIOS name release requests except from WINS
  servers to Enabled.

  This policy setting requires the installation of the MSS-Legacy custom
  templates included with the STIG package. MSS-Legacy.admx and
  MSS-Legacy.adml must be copied to the \\Windows\\PolicyDefinitions and
  \\Windows\\PolicyDefinitions\\en-US directories respectively."
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netbt\\Parameters') do
    it { should have_property 'NoNameReleaseOnDemand' }
    its('NoNameReleaseOnDemand') { should cmp 1 }
  end
end
