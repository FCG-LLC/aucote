"""
This module provides parsers used by Skipfish tool
"""
from ast import literal_eval
from os.path import sep
from shutil import rmtree
import ujson as json

from aucote_cfg import cfg
from tools.common.parsers import Parser
from tools.skipfish.structs import SkipfishIssuesDesc, SkipfishIssues, SkipfishIssueSample, SkipfishRisk


class SkipfishResultsParser(Parser):
    """
    Parser for skipfish issues

    """

    def __init__(self, directory):
        self.dir = directory
        self.severities = SkipfishIssuesDesc()

    def _parse_issues_desc(self, text):
        """
        Parses text and return SkipfishIssues object

        Args:
            text(str): content of index.html

        Returns:
            SkipfishIssuesDesc - description of skipfish issues

        """
        return_value = SkipfishIssuesDesc()
        cut_pre_start = text.index('var issue_desc=')
        cut_start = text.index('{', cut_pre_start)
        cut_end = text.index('}', cut_start)
        cut_text = text[cut_start:cut_end + 1]
        issues = json.loads(cut_text)

        return_value.add(issues)
        self.severities = return_value
        return return_value

    def _parse_index(self):
        """
        Parses index.html from skipfish log directory

        Returns:
            SkipfishIssuesDesc object

        """

        with open(sep.join((self.dir, 'index.html')), 'r') as report:
            self._parse_issues_desc(report.read())

    def _parse_samples(self):
        """
        Parses sample.js from skipfish log directory

        Returns:
            SkipfishIssues object

        """

        with open(sep.join((self.dir, 'samples.js')), 'r') as report:
            return self._parse_issues(report.read())

    def parse(self, stdout=None, stderr=None):
        """
        Parses skipfish report. stdout and stderr variables are not used

        """

        self._parse_index()
        return_value = self._parse_samples()
        rmtree(self.dir)
        return return_value

    def _parse_issues(self, text):
        """
        Parses issues basing on text variable

        Args:
            text(str): content of sample.js

        Returns:
            SkipfishIssues object

        """

        return_value = SkipfishIssues()
        cut_pre_start = text.index('var issue_samples')
        cut_start = text.index('[', cut_pre_start)
        cut_end = text.index('];', cut_start)
        cut_text = text[cut_start:cut_end + 1]
        issues = literal_eval(cut_text)

        for issue in issues:
            for sample in issue['samples']:
                return_value.add(SkipfishIssueSample(url=sample['url'], extra=sample['extra'], directory=sample['dir'],
                                                     severity_type=self.severities[issue['type']],
                                                     severity=SkipfishRisk.from_id(issue['severity']),
                                                     sid=sample['sid']))
        return return_value


class SkipfishOutputParser(Parser):
    """
    Provides functions for parsing skipfish stdout

    """
    def parse(self, stdout, stderr=None):
        """
        Prepares skipfish's report parser

        Args:
            stdout (str): skipfish's stdout
            stderr (str): skipfish's stderr

        Returns:
            SkipfishIssues object

        """
        parser = SkipfishResultsParser(directory=self._get_log_dir(output=stdout,
                                                                   directory=cfg['tools.skipfish.tmp_directory']))
        return parser.parse()

    def _get_log_dir(self, output, directory):
        """
        Parse skipfish output and return path to log directory

        Args:
            output (str): stdout from skipfish
            directory (str): path to the skipfish reports directory

        Returns:
            path to the logs directory

        """

        for line in output.split("\n"):
            if 'Report saved' in line:
                start_cut = line.index(directory)
                end_cut = line.index('/index.html')
                return line[start_cut:end_cut]
