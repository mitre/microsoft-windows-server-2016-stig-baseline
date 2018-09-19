control "V-73411" do
  title "Event Viewer must be protected from unauthorized modification and
  deletion."
  desc  "Protecting audit information also includes identifying and protecting
  the tools used to view and manipulate log data. Therefore, protecting audit
  tools is necessary to prevent unauthorized operation on audit information.

      Operating systems providing tools to interface with audit information will
  leverage user permissions and roles identifying the user accessing the tools
  and the corresponding rights the user enjoys in order to make access decisions
  regarding the modification or deletion of audit tools.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000257-GPOS-00098"
  tag "satisfies": ["SRG-OS-000257-GPOS-00098", "SRG-OS-000258-GPOS-00099"]
  tag "gid": "V-73411"
  tag "rid": "SV-88063r1_rule"
  tag "stig_id": "WN16-AU-000060"
  tag "fix_id": "F-79853r1_fix"
  tag "cci": ["CCI-001494", "CCI-001495"]
  tag "nist": ["AU-9", "Rev_4"]
  tag "documentable": false
  tag "check": "Navigate to \"%SystemRoot%\\System32\".

  View the permissions on \"Eventvwr.exe\".

  If any groups or accounts other than TrustedInstaller have \"Full control\" or
  \"Modify\" permissions, this is a finding.

  The default permissions below satisfy this requirement:

  TrustedInstaller - Full Control
  Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES, ALL RESTRICTED
  APPLICATION PACKAGES - Read & Execute"
  tag "fix": "Configure the permissions on the \"Eventvwr.exe\" file to prevent
  modification by any groups or accounts other than TrustedInstaller. The default
  permissions listed below satisfy this requirement:

  TrustedInstaller - Full Control
  Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES, ALL RESTRICTED
  APPLICATION PACKAGES - Read & Execute

  The default location is the \"%SystemRoot%\\ System32\" folder."
  get_system_root = command("env | Findstr SYSTEMROOT").stdout.strip
  system_root = get_system_root[11..get_system_root.length]
  describe.one do
    describe command("Get-Acl -Path '#{system_root}\\SYSTEM32\\Eventvwr.exe' | Format-List | Findstr All") do
      its('stdout') { should eq "Access : NT AUTHORITY\\SYSTEM Allow  ReadAndExecute, Synchronize\r\n         BUILTIN\\Administrators Allow  ReadAndExecute, Synchronize\r\n         BUILTIN\\Users Allow  ReadAndExecute, Synchronize\r\n         NT SERVICE\\TrustedInstaller Allow  FullControl\r\n         APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize\r\n" }
    end
    describe command("Get-Acl -Path '#{system_root}\\SYSTEM32\\Eventvwr.exe' | Format-List | Findstr All") do
      its('stdout') { should eq "Access : NT AUTHORITY\\SYSTEM Allow  ReadAndExecute, Synchronize\r\n         BUILTIN\\Administrators Allow  ReadAndExecute, Synchronize\r\n         BUILTIN\\Users Allow  ReadAndExecute, Synchronize\r\n         NT SERVICE\\TrustedInstaller Allow  FullControl\r\n         APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize\r\n         APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize\r\n" }
    end
  end
end

