class Enum4linuxResult(object):
    def __init__(self, os_result=None, users=None, shares=None):
        self.os_result = os_result
        self.users = users or []
        self.shares = shares or []
        self.local_groups = []
        self.domain_groups = []
        self.builtin_groups = []
        self.password_policy = None

    def __str__(self):
        return_value = ""
        if self.os_result:
            return_value += "Operating System: {0}\n\n".format(self.os_result.server)

        if self.users:
            return_value += "Users:\n{0}\n\n".format("\n".join(" - {0}".format(user) for user in self.users))

        if self.shares:
            return_value += "Shares:\n{0}\n\n".format("\n".join(" - {0}".format(share) for share in self.shares))

        if self.local_groups:
            return_value += "Local groups:\n{0}\n\n".format("\n".join(" - {0}".format(group)
                                                                      for group in self.local_groups))
        if self.domain_groups:
            return_value += "Domain groups:\n{0}\n\n".format("\n".join(" - {0}".format(group)
                                                                       for group in self.domain_groups))
        if self.builtin_groups:
            return_value += "Builtin groups:\n{0}\n\n".format("\n".join(" - {0}".format(group)
                                                                        for group in self.builtin_groups))
        if self.password_policy:
            return_value += "Password policy:\n{0}\n\n".format(self.password_policy)

        return return_value.strip("\n")


class Enum4linuxOS(object):
    def __init__(self, domain, os, server):
        self.server = server
        self.domain = domain
        self.os = os

    def __str__(self):
        return "OS for {self.domain} is {self.os}"

    def __eq__(self, other):
        return isinstance(other, Enum4linuxOS) and self.server == other.server and self.domain == other.domain and \
               self.os == other.os


class Enum4linuxUser(object):
    def __init__(self, index, rid, acb, account, name, desc):
        self.index = index
        self.rid = rid
        self.acb = acb
        self.account = account
        self.name = name if name != "(null)" else None
        self.desc = desc if desc != "(null)" else None

    def __str__(self):
        return self.account

    def __eq__(self, other):
        return isinstance(other, Enum4linuxUser) and self.index == other.index and self.rid == other.rid and \
               self.acb == other.acb and self.account == other.account and self.name == other.name and \
               self.desc == other.desc

    def __hash__(self):
        return hash((self.index, self.rid, self.acb, self.account, self.name, self.desc))


class Enum4linuxShare(object):
    def __init__(self, name, share_type=None, comment=None):
        self.name = name
        self.type = share_type
        self.comment = comment
        self.mapping = None
        self.listing = None

    def __str__(self):
        return self.name

    def __eq__(self, other):
        return isinstance(other, Enum4linuxShare) and self.name == other.name

    def __hash__(self):
        return hash(self.name)


class Enum4linuxGroup(object):
    def __init__(self, name, rid):
        self.name = name
        self.rid = rid
        self.users = set()

    def __str__(self):
        return self.name

    def __eq__(self, other):
        return isinstance(other, Enum4linuxGroup) and self.name == other.name

    def __hash__(self):
        return hash(self.name)


class Enum4linuxPasswordPolicy(object):
    UNIQUE_ATTRIBUTES = ('min_length', 'complexity', 'history', 'max_age', 'cleartext', 'no_anon_change',
                         'no_clear_change', 'lockout_admins', 'reset_lockout', 'lockout_duration', 'lockout_threshold',
                         'force_logoff_time', 'min_age')

    def __init__(self, min_length=None, complexity=None, history=None, max_age=None, cleartext=None,
                 no_anon_change=None, no_clear_change=None, lockout_admins=None, reset_lockout=None,
                 lockout_duration=None, lockout_threshold=None, force_logoff_time=None, min_age=None):
        self.min_length = min_length
        self.complexity = complexity
        self.history = history
        self.max_age = max_age
        self.min_age = min_age
        self.cleartext = cleartext
        self.no_anon_change = no_anon_change
        self.no_clear_change = no_clear_change
        self.lockout_admins = lockout_admins
        self.reset_lockout = reset_lockout
        self.lockout_duration = lockout_duration
        self.lockout_threshold = lockout_threshold
        self.force_logoff_time = force_logoff_time

    def __eq__(self, other):
        return isinstance(other, Enum4linuxPasswordPolicy) and \
               all(getattr(self, name) == getattr(other, name) for name in self.UNIQUE_ATTRIBUTES)

    def __hash__(self):
        return hash(tuple(getattr(self, name) for name in self.UNIQUE_ATTRIBUTES))

    def __str__(self):
        return """ - Minimum password length: {min_length}
 - Password complexity: {complexity}
 - Password minimum age: {min_age}
 - Password maximum age: {max_age}
 - Password history length: {history}
""".format(min_length=self.min_length, complexity=self.complexity, min_age=self.min_age, max_age=self.max_age,
           history=self.history)
