from enum import Enum


class RiskLevel(Enum):
    """
    Risk level object

    """

    def __init__(self, txt, number):
        self.txt = txt
        self.number = number

    HIGH = ('High', 3)
    MEDIUM = ('Medium', 2)
    LOW = ('Low', 1)
    NONE = ('None', 0)

    @classmethod
    def from_name(cls, name):
        """
        Create RiskLevel object basing on string name

        Args:
            name: string representation of risk level, eg. "medium"

        Returns:
            RiskLevel object

        Raises:
            ValueError if not: High, Medium, Low or None

        """
        for val in cls:
            if val.txt == name:
                return val
        raise ValueError('Unsupported risk level name: %s' % name)