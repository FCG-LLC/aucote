import re

from tools.common.parsers import Parser


class Enum4linuxParser(Parser):
    OS_INFORMATION_REGEX = "Domain=\[(?P<domain>.*?)\].*?OS=\[(?P<os>.*?)\].*?Server=\[(?P<server>.*?)\]"
    OS_INFORMATION_REGEX_COMPILED = re.compile(OS_INFORMATION_REGEX)

    USERS_REGEX = 'index: (?P<index>.*?)RID: (?P<rid>.*?)acb: (?P<acb>.*?)Account: (?P<account>.*?)Name: (?P<name>.*?)Desc: (?P<desc>.*)'
    USERS_REGEX_COMPILED = re.compile(USERS_REGEX)

    SHARES_LIST_REGEX = "\s+Sharename.*?\n\n"
    SHARES_LIST_REGEX_COMPILED = re.compile(SHARES_LIST_REGEX, re.DOTALL | re.MULTILINE)

    SHARE_REGEX = "(?P<name>.*?)\s{4,}(?P<type>.*?)\s{4,}(?P<comment>.*)"
    SHARE_REGEX_COMPILED = re.compile(SHARE_REGEX)

    def parse(self, stdout, stderr=None):
        pass

    def parse_os_information(self, text):
        regex_result = self.OS_INFORMATION_REGEX_COMPILED.search(text)
        if not regex_result:
            return None

        return regex_result.groupdict()

    def parse_users(self, text):
        regex_results = self.USERS_REGEX_COMPILED.finditer(text)
        return [{key: item.strip() if item.strip() != '(null)' else None for key, item in result.groupdict().items()}
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

        return [{key: item.strip() if item.strip() != '(null)' else None for key, item in result.groupdict().items()}
                for result in iterator]