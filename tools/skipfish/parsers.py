"""
This module provids parsers used by Skipfish tool
"""
import json
from ast import literal_eval
from os.path import sep, dirname

from shutil import rmtree

from tools.common.parsers import Parser
from tools.skipfish.structs import SkipfishIssuesDesc, SkipfishIssues, SkipfishIssueSample


class SkipfishResultsParser(Parser):
    """
    Parser for skipfish issues
    """

    def __init__(self, directory):
        self.dir = directory
        self.severities = SkipfishIssuesDesc()

    def parse_issues_desc(self, text):
        """
        Parses text and return SkipfishIssues object
        Args:
            text:

        Returns:

        """
        return_value = SkipfishIssuesDesc()
        cut_pre_start = text.index('var issue_desc=')
        cut_start = text.index('{', cut_pre_start)
        cut_end = text.index('}', cut_start)
        cut_text = text[cut_start:cut_end+1]
        issues = json.loads(cut_text)

        return_value.add(issues)
        self.severities = return_value
        return return_value

    def parse_index(self):
        with open(sep.join((self.dir, 'index.html')), 'r') as f:
            self.parse_issues_desc(f.read())

    def parse_samples(self):
        with open(sep.join((self.dir, 'samples.js')), 'r') as f:
            return self.parse_issues(f.read())

    def parse(self, output=None):
        self.parse_index()
        return_value = self.parse_samples()
        rmtree(self.dir)
        return return_value

    def parse_issues(self, text):
        return_value = SkipfishIssues()
        cut_pre_start = text.index('var issue_samples')
        cut_start = text.index('[', cut_pre_start)
        cut_end = text.index('];', cut_start)
        cut_text = text[cut_start:cut_end+1]
        issues = literal_eval(cut_text)

        for issue in issues:
            for sample in issue['samples']:
                return_value.add(SkipfishIssueSample(url=sample['url'], extra=sample['extra'], directory=sample['dir'],
                                                     severity_type=self.severities[issue['type']],
                                                     severity=issue['severity'], sid=sample['sid']))
        return return_value


class SkipfishOutputParser(Parser):
    @classmethod
    def parse(cls, output):
        parser = SkipfishResultsParser(directory=cls.get_log_dir(output))
        return parser.parse()

    @classmethod
    def get_log_dir(cls, output):
        """
        Parse skipfish output and return path to log directory
        Args:
            output:

        Returns:

        """
        for line in output.split("\n"):
            if 'Report saved' in line:
                start_cut = line.index('tmp/')
                end_cut = line.index('/index.html')
                return line[start_cut:end_cut]