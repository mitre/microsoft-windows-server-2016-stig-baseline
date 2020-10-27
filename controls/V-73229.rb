control 'V-73229' do
  title "Manually managed application account passwords must be at least 14
  characters in length."
  desc "Application/service account passwords must be of sufficient length to
  prevent being easily cracked. Application/service accounts that are manually
  managed must have passwords at least 14 characters in length."
  impact 0.5
  tag "gtitle": 'SRG-OS-000078-GPOS-00046'
  tag "gid": 'V-73229'
  tag "rid": 'SV-87881r1_rule'
  tag "stig_id": 'WN16-00-000060'
  tag "fix_id": 'F-79673r1_fix'
  tag "cci": ['CCI-000205']
  tag "nist": ['IA-5 (1) (a)', 'Rev_4']
  tag "documentable": false
  desc "check", "Determine if manually managed application/service accounts
  exist. If none exist, this is NA.

  Verify the organization has a policy to ensure passwords for manually managed
  application/service accounts are at least 14 characters in length.

  If such a policy does not exist or has not been implemented, this is a finding."
  desc "fix", "Establish a policy that requires application/service account
  passwords that are manually managed to be at least 14 characters in length.
  Ensure the policy is enforced."
  describe security_policy do
    its('MinimumPasswordLength') { should be >= 14 }
  end
end
