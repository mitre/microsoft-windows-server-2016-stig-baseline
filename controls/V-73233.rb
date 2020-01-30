control 'V-73233' do
  title 'Shared user accounts must not be permitted on the system.'
  desc  "Shared accounts (accounts where two or more people log on with the
  same user identification) do not provide adequate identification and
  authentication. There is no way to provide for non repudiation or individual
  accountability for system access and resource usage."
  impact 0.5
  tag "gtitle": 'SRG-OS-000104-GPOS-00051'
  tag "gid": 'V-73233'
  tag "rid": 'SV-87885r2_rule'
  tag "stig_id": 'WN16-00-000080'
  tag "fix_id": 'F-86117r1_fix'
  tag "cci": ['CCI-000764']
  tag "nist": ['IA-2', 'Rev_4']
  tag "documentable": false
  desc "check", "Determine whether any shared accounts exist. If no shared
  accounts exist, this is NA.

  Shared accounts, such as required by an application, may be approved by the
  organization.  This must be documented with the ISSO. Documentation must
  include the reason for the account, who has access to the account, and how the
  risk of using the shared account is mitigated to include monitoring account
  activity.

  If unapproved shared accounts exist, this is a finding."
  desc "fix", "Remove unapproved shared accounts from the system.

  Document required shared accounts with the ISSO. Documentation must include the
  reason for the account, who has access to the account, and how the risk of
  using the shared account is mitigated to include monitoring account activity."
  get_accounts = command("net user | Findstr /v 'command -- accounts'").stdout.strip.split(' ')
  shared_accounts = attribute('shared_accounts')

  if shared_accounts.empty?
    impact 0.0
    desc 'This system does not have any shared accounts, therefore this control is not applicable'
    describe 'This system does not have any shared accounts, therefore this control is not applicable' do
      skip 'This system does not have any shared accounts, therefore this control is not applicable'
    end
  else
    get_accounts.each do |user|
      describe user do
        it { should_not be_in shared_accounts }
      end
    end
  end
end
