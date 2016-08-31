"""
Provides Structs for Skipfish tool
"""

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
        Udate issues with data dictionary
        Args:
            data:

        Returns:

        """
        assert isinstance(data, dict)
        self._issues = {**self._issues, **data}

    def __getitem__(self, item):
        """
        Returns issue by item
        Args:
            item:

        Returns:

        """
        return self._issues.get(str(item), "Unknown")


class SkipfishIssueSample(object):
    """
    Provides objects contain detail information about issue sample from skipfish report
    """

    def __init__(self, severity, severity_type, url, extra, sid, directory):
        self.severity = severity
        self.type = severity_type
        self.url = url
        self.extra = extra
        self.sid = sid
        self.dir = directory

    def __str__(self):
        return self.url


class SkipfishIssues(object):
    """
    Provides collection of skipfish issues
    """
    SEVERITIES = {
        0: "Informational note",
        1: "Internal warning",
        2: "Low risk or low specificity",
        3: "Medium risk - data compromise",
        4: "High risk: system compromise",
    }

    def __init__(self):
        self._issues = []
        self._sorted_issues = {
            0: {},
            1: {},
            2: {},
            3: {},
            4: {}
        }

    def add(self, issue):
        self._issues.append(issue)
        self._sorted_issues[issue.severity].setdefault(issue.type, []).append(issue)

    def get_by_severity(self, severity):
        result = []
        for key, element in self._sorted_issues[severity].items():
            result.extend(element)
        return result

    def __str__(self):
        return_value = ''
        for i in range(4, -1, -1):
            if self._sorted_issues[i].keys():
                return_value += '''
{0}:'''.format(self.SEVERITIES[i])
                for severity, samples in self._sorted_issues[i].items():
                    return_value += '''
    {0}:
        {1}'''.format(severity, "\n\t\t".join([str(sample) for sample in samples]))

        return return_value.strip()

    def __bool__(self):
        return any([issue for issue in self._issues if issue.severity > 1])
