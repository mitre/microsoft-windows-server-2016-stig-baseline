control 'V-73273' do
  title "Systems requiring data at rest protections must employ cryptographic
  mechanisms to prevent unauthorized disclosure and modification of the
  information at rest."
  desc "This requirement addresses protection of user-generated data as well
  as operating system-specific configuration data. Organizations may choose to
  employ different mechanisms to achieve confidentiality and integrity
  protections, as appropriate, in accordance with the security category and/or
  classification of the information.

  Selection of a cryptographic mechanism is based on the need to protect the
  integrity of organizational information. The strength of the mechanism is
  commensurate with the security category and/or classification of the
  information. Organizations have the flexibility to either encrypt all
  information on storage devices (i.e., full disk encryption) or encrypt specific
  data structures (e.g., files, records, or fields).
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000185-GPOS-00079'
  tag "satisfies": ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183',
                    'SRG-OS-000405-GPOS-00184']
  tag "gid": 'V-73273'
  tag "rid": 'SV-87925r1_rule'
  tag "stig_id": 'WN16-00-000280'
  tag "fix_id": 'F-79717r1_fix'
  tag "cci": ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag "nist": ['SC-28', 'SC-28 (1)', 'Rev_4']
  tag "documentable": false
  desc "check", "Verify systems that require additional protections due to
  factors such as inadequate physical protection or sensitivity of the data
  employ encryption to protect the confidentiality and integrity of all
  information at rest.

  If they do not, this is a finding."
  desc "fix", "Configure systems that require additional protections due to
  factors such as inadequate physical protection or sensitivity of the data to
  employ encryption to protect the confidentiality and integrity of all
  information at rest."
  describe "A manual review is required to verify that systems requiring data at rest protections are employing cryptographic
  mechanisms to prevent unauthorized disclosure and modification of the
  information at rest." do
    skip "A manual review is required to verify that systems requiring data at rest protections are employing cryptographic
  mechanisms to prevent unauthorized disclosure and modification of the
  information at rest."
  end
end
