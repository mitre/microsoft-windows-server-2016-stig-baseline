control "V-73271" do
  title "Software certificate installation files must be removed from Windows
  Server 2016."
  desc  "Use of software certificates and their accompanying installation files
  for end users to access resources is less secure than the use of hardware-based
  certificates."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73271"
  tag "rid": "SV-87923r1_rule"
  tag "stig_id": "WN16-00-000270"
  tag "fix_id": "F-79715r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "Search all drives for *.p12 and *.pfx files.

  If any files with these extensions exist, this is a finding.

  This does not apply to server-based applications that have a requirement for
  certificate files. Some applications create files with extensions of .p12 that
  are not certificate installation files. Removal of non-certificate installation
  files from systems is not required. These must be documented with the ISSO."
  tag "fix": "Remove any certificate installation files (*.p12 and *.pfx) found
  on a system.

  This does not apply to server-based applications that have a requirement for
  certificate files."
  describe command('where /R c: *.p12 *.pfx') do
    its('stdout') { should eq "" }
  end
end

