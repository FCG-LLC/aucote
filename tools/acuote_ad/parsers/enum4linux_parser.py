import re

from tools.acuote_ad.structs import Enum4linuxOS, Enum4linuxUser, Enum4linuxResult, Enum4linuxShare, Enum4linuxGroup, \
    Enum4linuxPasswordPolicy
from tools.common.parsers import Parser


class Enum4linuxParser(Parser):
    OS_INFORMATION_REGEX_SECTION_COMPILED = re.compile(r'\s+[=]+\s+\|\s+OS information.*?[=]+\s+.*?([=]{7,}|$)',
                                                       re.DOTALL | re.MULTILINE)

    USERS_REGEX_SECTION_COMPILED = re.compile(r'\s+[=]+\s+\|\s+Users.*?[=]+\s+.*?([=]{7,})', re.DOTALL | re.MULTILINE)

    SHARES_REGEX_SECTION_COMPILED = re.compile(r'\s+[=]+\s+\|\s+Share Enumeration.*?[=]+\s+.*?([=]{7,})',
                                               re.DOTALL | re.MULTILINE)

    PASSWORD_POLICY_SECTION_COMPILED = re.compile(r'\s+[=]+\s+\|\s+Password Policy Information.*?[=]+\s+.*?([=]{7,})',
                                                  re.DOTALL | re.MULTILINE)

    OS_INFORMATION_REGEX_COMPILED = re.compile(r'Domain=\[(?P<domain>.*?)\].*?OS=\[(?P<os>.*?)\].*?Server='
                                               '\[(?P<server>.*?)\]')

    USERS_REGEX_COMPILED = re.compile(r'index: (?P<index>.*?)RID: (?P<rid>.*?)acb: (?P<acb>.*?)'
                                      'Account: (?P<account>.*?)Name: (?P<name>.*?)Desc: (?P<desc>.*)')

    SHARES_LIST_REGEX_COMPILED = re.compile(r'\s+Sharename.*?(\n\n)', re.DOTALL | re.MULTILINE)

    SHARE_REGEX_COMPILED = re.compile(r'(?P<name>.*?)\s{4,}(?P<share_type>.*?)\s{4,}(?P<comment>.*)')

    GROUP_REGEX_COMPILED = re.compile(r'group\:\[(?P<name>.*?)\]\s+rid\:\[(?P<rid>.*?)\]')

    GROUP_USER_REGEX_COMPILED = re.compile(r'Group \'(?P<group>.*?)\'.*?has member\:\s+(?P<name>.*)')

    LOCAL_GROUPS_REGEX_COMPILED = re.compile(r'\[\+\] Getting local groups\:.*?(\[\+\] Getting local group memberships)'
                                             '.*?(\[\+\]|\n\n)', re.DOTALL | re.MULTILINE)

    BUILTIN_GROUPS_REGEX_COMPILED = re.compile(r'\[\+\] Getting builtin groups\:.*?(\[\+\] Getting builtin group '
                                               'memberships).*?(\[\+\]|\n\n)', re.DOTALL | re.MULTILINE)

    DOMAIN_GROUPS_REGEX_COMPILED = re.compile(r'\[\+\] Getting domain groups\:.*?(\[\+\] Getting domain group '
                                              'memberships).*?(\[\+\]|\n\n)', re.DOTALL | re.MULTILINE)

    PP_MIN_PASS_REGEX_COMPILED = re.compile(r'Minimum password length: (?P<min_length>.*)')
    PP_HISTORY_REGEX_COMPILED = re.compile(r'Password history length: (?P<history>.*)')
    PP_MAX_AGE_REGEX_COMPILED = re.compile(r'Maximum password age: (?P<max_age>.*)')
    PP_CLEAR_REGEX_COMPILED = re.compile(r'Domain Password Store Cleartext: (?P<cleartext>.*)')
    PP_LOCKOUT_REGEX_COMPILED = re.compile(r'Domain Password Lockout Admins: (?P<lockout_admins>.*)')
    PP_NO_CLEAR_REGEX_COMPILED = re.compile(r'Domain Password No Clear Change: (?P<no_clear_change>.*)')
    PP_NO_ANON_REGEX_COMPILED = re.compile(r'Domain Password No Anon Change: (?P<no_anon_change>.*)')
    PP_COMPLEXITY_REGEX_COMPILED = re.compile(r'Domain Password Complex: (?P<complexity>.*)')
    PP_MIN_AGE_REGEX_COMPILED = re.compile(r'Minimum password age: (?P<min_age>.*)')
    PP_RESET_REGEX_COMPILED = re.compile(r'Reset Account Lockout Counter: (?P<reset_lockout>.*)')
    PP_DURATION_REGEX_COMPILED = re.compile(r'Locked Account Duration: (?P<lockout_duration>.*)')
    PP_THRESHOLD_REGEX_COMPILED = re.compile(r'Account Lockout Threshold: (?P<lockout_threshold>.*)')
    PP_LOGOFF_REGEX_COMPILED = re.compile(r'Forced Log off Time: (?P<force_logoff_time>.*)')
    
    PP_REGEXES = (
        PP_MIN_PASS_REGEX_COMPILED, PP_HISTORY_REGEX_COMPILED, PP_MAX_AGE_REGEX_COMPILED, PP_CLEAR_REGEX_COMPILED,
        PP_LOCKOUT_REGEX_COMPILED, PP_NO_CLEAR_REGEX_COMPILED, PP_NO_ANON_REGEX_COMPILED, PP_COMPLEXITY_REGEX_COMPILED, 
        PP_MIN_AGE_REGEX_COMPILED, PP_RESET_REGEX_COMPILED, PP_DURATION_REGEX_COMPILED, PP_THRESHOLD_REGEX_COMPILED,
        PP_LOGOFF_REGEX_COMPILED
    )

    def parse(self, stdout, stderr=None):
        return_value = Enum4linuxResult()
        os_information_regex_result = self.OS_INFORMATION_REGEX_SECTION_COMPILED.search(stdout)
        shares_regex_result = self.SHARES_REGEX_SECTION_COMPILED.search(stdout)
        users_regex_result = self.USERS_REGEX_SECTION_COMPILED.search(stdout)
        password_policy_result = self.PASSWORD_POLICY_SECTION_COMPILED.search(stdout)

        if os_information_regex_result:
            return_value.os_result = self.parse_os_information(os_information_regex_result.group())

        if shares_regex_result:
            return_value.shares = self.parse_shares(shares_regex_result.group())

        if users_regex_result:
            return_value.users = self.parse_users(users_regex_result.group())

        if password_policy_result and "Skipping this check" not in password_policy_result.group():
            return_value.password_policy = self.parse_password_policy(password_policy_result.group())

        groups = self.parse_groups(stdout)
        return_value.local_groups = groups.get('local')
        return_value.domain_groups = groups.get('domain')
        return_value.builtin_groups = groups.get('builtin')

        return return_value

    def parse_os_information(self, text):
        regex_result = self.OS_INFORMATION_REGEX_COMPILED.search(text)
        if not regex_result:
            return None

        return Enum4linuxOS(**regex_result.groupdict())

    def parse_users(self, text):
        regex_results = self.USERS_REGEX_COMPILED.finditer(text)
        return [Enum4linuxUser(**{key: item.strip() for key, item in result.groupdict().items()})
                for result in regex_results]

    def parse_shares(self, text):
        regex_result = self.SHARES_LIST_REGEX_COMPILED.search(text)
        if not regex_result:
            return None

        return self.parse_shares_list(regex_result.group())

    def parse_shares_list(self, text):
        iterator = self.SHARE_REGEX_COMPILED.finditer(text)
        try:  # Omit two first rows: header and horizontal line
            next(iterator)
            next(iterator)
        except StopIteration:
            return []

        return [Enum4linuxShare(**{key: item.strip() for key, item in result.groupdict().items()})
                for result in iterator]

    def parse_groups_list(self, text):
        groups = {}
        for group_regex in self.GROUP_REGEX_COMPILED.finditer(text):
            group = group_regex.groupdict()
            groups[group['name']] = Enum4linuxGroup(name=group['name'], rid=group['rid'])

        for user_regex in self.GROUP_USER_REGEX_COMPILED.finditer(text):
            user = user_regex.groupdict()
            groups[user['group']].users.update({user['name']})

        return groups.values()

    def parse_groups(self, text):
        local_groups = self.LOCAL_GROUPS_REGEX_COMPILED.search(text)
        domain_groups = self.DOMAIN_GROUPS_REGEX_COMPILED.search(text)
        builtin_groups = self.BUILTIN_GROUPS_REGEX_COMPILED.search(text)

        return {
            'builtin': self.parse_groups_list(builtin_groups.group() if builtin_groups else ''),
            'local': self.parse_groups_list(local_groups.group() if local_groups else ''),
            'domain': self.parse_groups_list(domain_groups.group() if domain_groups else '')
        }

    def parse_password_policy(self, text):
        params = {}
        for regex in self.PP_REGEXES:
            group = regex.search(text)
            if group:
                params.update(group.groupdict())
        params = {key: value.strip() for key, value in params.items()}
        return Enum4linuxPasswordPolicy(**params)
