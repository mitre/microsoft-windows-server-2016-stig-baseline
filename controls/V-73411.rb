control 'V-73411' do
  title "Event Viewer must be protected from unauthorized modification and
  deletion."
  desc "Protecting audit information also includes identifying and protecting
  the tools used to view and manipulate log data. Therefore, protecting audit
  tools is necessary to prevent unauthorized operation on audit information.

      Operating systems providing tools to interface with audit information will
  leverage user permissions and roles identifying the user accessing the tools
  and the corresponding rights the user enjoys in order to make access decisions
  regarding the modification or deletion of audit tools.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000257-GPOS-00098'
  tag "satisfies": ['SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag "gid": 'V-73411'
  tag "rid": 'SV-88063r1_rule'
  tag "stig_id": 'WN16-AU-000060'
  tag "fix_id": 'F-79853r1_fix'
  tag "cci": ['CCI-001494', 'CCI-001495']
  tag "nist": ['AU-9', 'Rev_4']
  tag "documentable": false
  desc "check", "Navigate to %SystemRoot%\\System32.

  View the permissions on Eventvwr.exe.

  If any groups or accounts other than TrustedInstaller have Full control or
  Modify permissions, this is a finding.

  The default permissions below satisfy this requirement:

  TrustedInstaller - Full Control
  Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES, ALL RESTRICTED
  APPLICATION PACKAGES - Read & Execute"
  desc "fix", "Configure the permissions on the Eventvwr.exe file to prevent
  modification by any groups or accounts other than TrustedInstaller. The default
  permissions listed below satisfy this requirement:

  TrustedInstaller - Full Control
  Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES, ALL RESTRICTED
  APPLICATION PACKAGES - Read & Execute

  The default location is the %SystemRoot%\\ System32 folder."

  system_root = command('$env:SystemRoot').stdout.strip

  describe.one do
    describe file("#{system_root}\\System32\\eventvwr.exe") do
      it { should be_allowed('read', by_user: 'NT AUTHORITY\\SYSTEM') }
      it { should be_allowed('read', by_user: 'BUILTIN\\Administrators') }
      it { should be_allowed('read', by_user: 'BUILTIN\\Users') }
      it { should be_allowed('full-control', by_user: 'NT SERVICE\\TrustedInstaller') }
      it { should be_allowed('read', by_user: 'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES') }
    end

    describe file("#{system_root}\\System32\\eventvwr.exe") do
      it { should be_allowed('read', by_user: 'NT AUTHORITY\\SYSTEM') }
      it { should be_allowed('read', by_user: 'BUILTIN\\Administrators') }
      it { should be_allowed('read', by_user: 'BUILTIN\\Users') }
      it { should be_allowed('full-control', by_user: 'NT SERVICE\\TrustedInstaller') }
      it { should be_allowed('read', by_user: 'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES') }
      it { should be_allowed('read', by_user: 'APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES\\ALL APPLICATION PACKAGES') }
    end
  end
end
