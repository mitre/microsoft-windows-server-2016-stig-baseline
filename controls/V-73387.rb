control 'V-73387' do
  title "The directory service must be configured to terminate LDAP-based
  network connections to the directory server after 5 minutes of inactivity."
  desc "The failure to terminate inactive network connections increases the
  risk of a successful attack on the directory server. The longer an established
  session is in progress, the more time an attacker has to hijack the session,
  implement a means to passively intercept data, or compromise any protections on
  client access. For example, if an attacker gains control of a client computer,
  an existing (already authenticated) session with the directory server could
  allow access to the directory. The lack of confidentiality protection in
  LDAP-based sessions increases exposure to this vulnerability."
  impact 0.3
  tag "gtitle": 'SRG-OS-000163-GPOS-00072'
  tag "gid": 'V-73387'
  tag "rid": 'SV-88039r1_rule'
  tag "stig_id": 'WN16-DC-000160'
  tag "fix_id": 'F-79829r1_fix'
  tag "cci": ['CCI-001133']
  tag "nist": ['SC-10', 'Rev_4']
  tag "documentable": false
  tag "check": "This applies to domain controllers. It is NA for other systems.

  Open an elevated Command Prompt (run as administrator).

  Enter ntdsutil.

  At the ntdsutil: prompt, enter LDAP policies.

  At the ldap policy: prompt, enter connections.

  At the server connections: prompt, enter connect to server [host-name]
  (where [host-name] is the computer name of the domain controller).

  At the server connections: prompt, enter q.

  At the ldap policy: prompt, enter show values.

  If the value for MaxConnIdleTime is greater than 300 (5 minutes) or is not
  specified, this is a finding.

  Enter q at the ldap policy: and ntdsutil: prompts to exit.

  Alternately, Dsquery can be used to display MaxConnIdleTime:

  Open Command Prompt (Admin).
  Enter the following command (on a single line).

  dsquery * cn=Default Query Policy,cn=Query-Policies,cn=Directory Service,
  cn=Windows NT,cn=Services,cn=Configuration,dc=[forest-name] -attr
  LDAPAdminLimits

  The quotes are required and dc=[forest-name] is the fully qualified LDAP name
  of the domain being reviewed (e.g., dc=disaost,dc=mil).

  If the results do not specify a MaxConnIdleTime or it has a value greater
  than 300 (5 minutes), this is a finding."
  tag "fix": "Configure the directory service to terminate LDAP-based network
  connections to the directory server after 5 minutes of inactivity.

  Open an elevated Command prompt (run as administrator).

  Enter ntdsutil.

  At the ntdsutil: prompt, enter LDAP policies.

  At the ldap policy: prompt, enter connections.

  At the server connections: prompt, enter connect to server [host-name]
  (where [host-name] is the computer name of the domain controller).

  At the server connections: prompt, enter q.

  At the ldap policy: prompt, enter Set MaxConnIdleTime to 300.

  Enter Commit Changes to save.

  Enter Show values to verify changes.

  Enter q at the ldap policy: and ntdsutil: prompts to exit."
  max_conn_idle_time = input('max_conn_idle_time')
  forrest = attribute('forrest')
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  names = []
  query = command("dsquery * 'cn=Default Query Policy,cn=Query-Policies,cn=Directory Service,
  cn=Windows NT,cn=Services,cn=Configuration,#{forrest}' -attr LDAPAdminLimits").stdout.strip.split(';')
  query.each do |data|
    loc_equalsign = data.index('=')
    name = data[0..loc_equalsign-1]
    names.push(name)
    value_start = loc_equalsign+1
    value = data[value_start..-1]
    if name == 'MaxConnIdleTime'
      MaxConnIdleTime = value
    end
  end
  if domain_role == '4' || domain_role == '5'
    [names].each do |n|
      describe 'The ldapadminlimits' do
        subject { n }
        it { should include 'MaxConnIdleTime' }
      end
    end

    describe 'The MaxConnIdleTime' do
      subject { max_conn_idle_time }
      it { should cmp <= 300 }
    end
  end

  if !(domain_role == '4') && !(domain_role == '5')
    impact 0.0
    desc 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end
