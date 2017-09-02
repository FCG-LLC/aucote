import re

from tools.acuote_ad.structs import Enum4linuxOS, Enum4linuxUser, Enum4linuxResult, Enum4linuxShare, Enum4linuxGroup
from tools.common.parsers import Parser


class Enum4linuxParser(Parser):
    OS_INFORMATION_REGEX_SECTION = "\s+[=]+\s+\|\s+OS information.*?[=]+\s+.*?([=]{7,}|$)"
    OS_INFORMATION_REGEX_SECTION_COMPILED = re.compile(OS_INFORMATION_REGEX_SECTION, re.DOTALL | re.MULTILINE)

    USERS_REGEX_SECTION = "\s+[=]+\s+\|\s+Users.*?[=]+\s+.*?([=]{7,})"
    USERS_REGEX_SECTION_COMPILED = re.compile(USERS_REGEX_SECTION, re.DOTALL | re.MULTILINE)

    SHARES_REGEX_SECTION = "\s+[=]+\s+\|\s+Share Enumeration.*?[=]+\s+.*?([=]{7,})"
    SHARES_REGEX_SECTION_COMPILED = re.compile(SHARES_REGEX_SECTION, re.DOTALL | re.MULTILINE)

    OS_INFORMATION_REGEX = "Domain=\[(?P<domain>.*?)\].*?OS=\[(?P<os>.*?)\].*?Server=\[(?P<server>.*?)\]"
    OS_INFORMATION_REGEX_COMPILED = re.compile(OS_INFORMATION_REGEX)

    USERS_REGEX = 'index: (?P<index>.*?)RID: (?P<rid>.*?)acb: (?P<acb>.*?)Account: (?P<account>.*?)Name: (?P<name>.*?)Desc: (?P<desc>.*)'
    USERS_REGEX_COMPILED = re.compile(USERS_REGEX)

    SHARES_LIST_REGEX = "\s+Sharename.*?(\n\n)"
    SHARES_LIST_REGEX_COMPILED = re.compile(SHARES_LIST_REGEX, re.DOTALL | re.MULTILINE)

    SHARE_REGEX = "(?P<name>.*?)\s{4,}(?P<share_type>.*?)\s{4,}(?P<comment>.*)"
    SHARE_REGEX_COMPILED = re.compile(SHARE_REGEX)

    GROUP_REGEX = "group\:\[(?P<name>.*?)\]\s+rid\:\[(?P<rid>.*?)\]"
    GROUP_REGEX_COMPILED = re.compile(GROUP_REGEX)

    GROUP_USER_REGEX = "Group '(?P<group>.*?)'.*?has member\:\s+(?P<name>.*)"
    GROUP_USER_REGEX_COMPILED = re.compile(GROUP_USER_REGEX)

    LOCAL_GROUPS_REGEX = "\[\+\] Getting local groups\:.*?(\[\+\] Getting local group memberships).*?(\[\+\]|\n\n)"
    LOCAL_GROUPS_REGEX_COMPILED = re.compile(LOCAL_GROUPS_REGEX, re.DOTALL | re.MULTILINE)

    BUILTIN_GROUPS_REGEX = "\[\+\] Getting builtin groups\:.*?(\[\+\] Getting builtin group memberships).*?(\[\+\]|\n\n)"
    BUILTIN_GROUPS_REGEX_COMPILED = re.compile(BUILTIN_GROUPS_REGEX, re.DOTALL | re.MULTILINE)

    DOMAIN_GROUPS_REGEX = "\[\+\] Getting domain groups\:.*?(\[\+\] Getting domain group memberships).*?(\[\+\]|\n\n)"
    DOMAIN_GROUPS_REGEX_COMPILED = re.compile(DOMAIN_GROUPS_REGEX, re.DOTALL | re.MULTILINE)

    def parse(self, stdout, stderr=None):
        return_value = Enum4linuxResult()
        os_information_regex_result = self.OS_INFORMATION_REGEX_SECTION_COMPILED.search(stdout)
        shares_regex_result = self.SHARES_REGEX_SECTION_COMPILED.search(stdout)
        users_regex_result = self.USERS_REGEX_SECTION_COMPILED.search(stdout)

        if os_information_regex_result:
            return_value.os_result = self.parse_os_information(os_information_regex_result.group())

        if shares_regex_result:
            return_value.shares = self.parse_shares(shares_regex_result.group())

        if users_regex_result:
            return_value.users = self.parse_users(users_regex_result.group())

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
        try:
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