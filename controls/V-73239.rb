control "V-73239" do
  title "Systems must be maintained at a supported servicing level."
  desc  "Systems at unsupported servicing levels will not receive security
  updates for new vulnerabilities, which leave them subject to exploitation.
  Systems must be maintained at a servicing level supported by the vendor with
  new security updates."
  impact 0.7
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-73239"
  tag "rid": "SV-87891r1_rule"
  tag "stig_id": "WN16-00-000110"
  tag "fix_id": "F-79683r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "Open \"Command Prompt\".

  Enter \"winver.exe\".

  If the \"About Windows\" dialog box does not display \"Microsoft Windows Server
  Version 1607 (Build 14393.xxx)\" or greater, this is a finding.

  Preview versions must not be used in a production environment."
  tag "fix": "Update the system to a Version 1607 (Build 14393.xxx) or greater."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion") do
    it { should have_property "CurrentMajorVersionNumber" }
    its("CurrentMajorVersionNumber") { should cmp >= 10 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion") do
    it { should have_property "CurrentBuildNumber" }
    its("CurrentBuildNumber") { should cmp >= '14393' }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion") do
    it { should have_property "ReleaseId" }
    its("ReleaseId") { should cmp >= '1607' }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion") do
    it { should have_property "CurrentBuild" }
    its("CurrentBuild") { should cmp >= '14393' }
  end
end

