"""
Provides Structs for Skipfish tool
"""
from enum import Enum


class SkipfishIssuesDesc(object):
    """
    Collection of skipfish issues
    """

    def __init__(self):
        """
        initialize private issues dictionary
        """

        self._issues = {}

    def add(self, data):
        """
        Updates issues with data dictionary

        Args:
            data (dict):

        Returns:
            None

        """

        assert isinstance(data, dict)
        self._issues.update(data)

    def __getitem__(self, item):
        """
        Returns issue by item

        Args:
            item (int|str):

        Returns:
            None

        """

        return self._issues.get(str(item), "Unknown")


class SkipfishIssueSample(object):
    """
    Provides objects contain detail information about issue sample from skipfish report
    """

    def __init__(self, severity, severity_type, url, extra, sid, directory):
        """
        Args:
            severity (SkipfishRisk): SkipfishRisk (integer value)
            severity_type (str): Type of severity (short description)
            url (str): URL related to issue
            extra (str): Additional comment
            sid (str): Unknown
            directory (str): Location of detailed report

        """

        self.severity = severity
        self.type = severity_type
        self.url = url
        self.extra = extra
        self.sid = sid
        self.dir = directory

    def __str__(self):
        """
        String reresentation of object

        Returns:
            str: representation of issues sample

        """

        return self.url


class SkipfishRisk(Enum):
    """
    Represents Risks used by skipfish.
    """
    NOTE = (0, "Informational note")
    WARNING = (1, "Internal warning")
    LOW_RISK = (2, "Low risk or low specificity")
    MEDIUM_RISK = (3, "Medium risk - data compromise")
    HIGH_RISK = (4, "High risk: system compromise")

    def __init__(self, num, description):
        """
        Init object

        Args:
            num (int): skipfish's risk id
            description: skipfish's risk description

        """

        self.num = num
        self.description = description

    @classmethod
    def from_id(cls, skipfish_id):
        """
        Returns SkipfishRisk object basing on passed skipfish_id

        Args:
            skipfish_id(int): id of skipfish risk

        Returns:
            SkipfishRisk

        """

        for val in cls:
            if val.num == skipfish_id:
                return val
        raise ValueError()


class SkipfishIssues(object):
    """
    Provides collection of skipfish issues
    """

    def __init__(self):
        """
        Init issues collections
        """

        self._issues = []
        self._sorted_issues = {}

    def add(self, issue):
        """
        Adds issue to the collection

        Args:
            issue (SkipfishIssueSample): Issue to adds to the collection

        Returns:
            None

        """

        self._issues.append(issue)
        self._sorted_issues.setdefault(issue.severity, {}).setdefault(issue.type, []).append(issue)

    def get_by_severity(self, severity):
        """
        Returns list of issues by passed severity

        Args:
            severity (SkipfishRisk):

        Returns:
            list

        """

        result = []
        for element in self._sorted_issues[severity].values():
            result.extend(element)
        return result

    def __str__(self):
        """
        Returns string representation of object

        Returns:
            str

        """

        return_value = ''
        for i in range(4, 1, -1):
            if self._sorted_issues.get(SkipfishRisk.from_id(i)):
                return_value += '''
{0}:'''.format(SkipfishRisk.from_id(i).description)
                for severity, samples in self._sorted_issues[SkipfishRisk.from_id(i)].items():
                    return_value += '''
    {0}:
        {1}'''.format(severity, "\n\t\t".join([str(sample) for sample in samples]))

        return return_value.strip()

    def __bool__(self):
        """
        Boolean rspresentation of object

        Returns:
            bool

        """

        return any([issue for issue in self._issues if issue.severity.num > 1])
