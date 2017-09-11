from unittest import TestCase

from tools.acuote_ad.parsers.enum4linux_parser import Enum4linuxParser
from tools.acuote_ad.structs import Enum4linuxOS, Enum4linuxUser, Enum4linuxShare, Enum4linuxGroup, \
    Enum4linuxPasswordPolicy


class Enum4linuxParserTest(TestCase):
    from tests.test_tools.test_aucote_ad.test_parsers.test_enum4linux_parser_input import PASSWORD_POLICY, OUTPUT, \
        LOCAL_GROUPS, GROUPS, DOMAIN_GROUPS, BUILTIN_GROUPS, SHARES, OS_INFORMATION, USERS

    def setUp(self):
        self.parser = Enum4linuxParser()

    def test_parse_os_information(self):
        result = self.parser.parse_os_information(self.OS_INFORMATION)
        expected = Enum4linuxOS(domain='CS', os='Windows Server 2012 R2 Standard 9600',
                                server='Windows Server 2012 R2 Standard 6.3')

        self.assertEqual(result, expected)

    def test_parse_users(self):
        result = self.parser.parse_users(self.USERS)
        expected = [
            Enum4linuxUser(index='0xf4d', rid='0x1f4', acb='0x00000010', account='Administrator', name=None,
                           desc='Built-in account for administering the computer/domain'),
            Enum4linuxUser(index='0x101e', rid='0x451', acb='0x00000210', account='jkowalski', name='Jan JK. Kowalski',
                           desc=None)
        ]

        self.assertEqual(result, expected)

    def test_parse_shares(self):
        result = self.parser.parse_shares(self.SHARES)
        expected = [
            Enum4linuxShare(name='ADMIN$', share_type='Disk', comment='Remote Admin'),
            Enum4linuxShare(name='C$', share_type='Disk', comment='Default share'),
            Enum4linuxShare(name='IPC$', share_type='IPC', comment='Remote IPC'),
            Enum4linuxShare(name='NETLOGON', share_type='Disk', comment='Logon server share'),
            Enum4linuxShare(name='SYSVOL', share_type='Disk', comment='Logon server share')
        ]

        self.assertCountEqual(result, expected)

    def test_parse_groups_list(self):
        result = self.parser.parse_groups_list(self.LOCAL_GROUPS)
        result_users = [group.users for group in result]

        expected = [
            Enum4linuxGroup(name='Cert Publishers', rid='0x205'),
            Enum4linuxGroup(name='Denied RODC Password Replication Group', rid='0x23c')
        ]

        expected_users = [set(), {'CS\krbtgt', 'CS\Domain Controllers', 'CS\Enterprise Admins',
                                  'CS\Read-only Domain Controllers'}]

        self.assertCountEqual(result, expected)
        self.assertCountEqual(result_users, expected_users)

    def test_parse_password_policy(self):
        result = self.parser.parse_password_policy(self.PASSWORD_POLICY)
        expected = Enum4linuxPasswordPolicy(min_length='7', complexity='1', history='24',
                                            max_age='41 days 23 hours 52 minutes', min_age='1 day', cleartext='0',
                                            no_anon_change='0', no_clear_change='0', lockout_admins='0',
                                            reset_lockout='30 minutes', lockout_duration='30 minutes',
                                            lockout_threshold='None', force_logoff_time='Not Set')

        self.assertEqual(result, expected)
