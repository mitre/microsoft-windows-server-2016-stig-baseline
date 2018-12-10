control 'V-73615' do
  title "PKI certificates associated with user accounts must be issued by the
  DoD PKI or an approved External Certificate Authority (ECA)."
  desc "A PKI implementation depends on the practices established by the
  Certificate Authority (CA) to ensure the implementation is secure. Without
  proper practices, the certificates issued by a CA have limited value in
  authentication functions."
  impact 0.7
  tag "gtitle": 'SRG-OS-000066-GPOS-00034'
  tag "gid": 'V-73615'
  tag "rid": 'SV-88279r2_rule'
  tag "stig_id": 'WN16-DC-000300'
  tag "fix_id": 'F-80065r1_fix'
  tag "cci": ['CCI-000185']
  tag "nist": ['IA-5 (2) (a)', 'Rev_4']
  tag "documentable": false
  tag "check": "This applies to domain controllers. It is NA for other systems.

  Review user account mappings to PKI certificates.

  Open \"Windows PowerShell\".

  Enter \"Get-ADUser -Filter * | FT Name, UserPrincipalName, Enabled\".

  Exclude disabled accounts (e.g., DefaultAccount, Guest) and the krbtgt account.

  If the User Principal Name (UPN) is not in the format of an individual's
  identifier for the certificate type and for the appropriate domain suffix, this
  is a finding.

  For standard NIPRNet certificates the individual's identifier is in the format
  of an Electronic Data Interchange - Personnel Identifier (EDI-PI).

  Alt Tokens and other certificates may use a different UPN format than the
  EDI-PI which vary by organization. Verified these with the organization.

  NIPRNet Example:
  Name - User Principal Name
  User1 - 1234567890@mil

  See PKE documentation for other network domain suffixes.

  If the mappings are to certificates issued by a CA authorized by the
  Component's CIO, this is a CAT II finding."
  tag "fix": "Map user accounts to PKI certificates using the appropriate User
  Principal Name (UPN) for the network. See PKE documentation for details."
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  query = command("Get-ADUser -Filter 'enabled -eq $true' | FT Name, UserPrincipalName | Findstr /v 'Name --- UserPrincipalName'").stdout.strip.split("\n")
  names = []
  user_principalnames = []
  query.each do |value|
    account_name = value[0..12]
    names.push(account_name)
    userprincipalname = value[14..-1]

    user_principalnames.push(userprincipalname)
  end

  user_principalnames.each do |principalname|
    principalname.strip
    describe principalname do
      it { should match(/[\w*]@mil/) }
    end
  end if [4, 5].include? domain_role

  if ![4, 5].include? domain_role
    impact 0.0
    desc 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end
