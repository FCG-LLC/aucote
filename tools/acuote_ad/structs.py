class Enum4linuxResult(object):
    def __init__(self, os_result=None, users=None, shares=None):
        self.os_result = os_result
        self.users = users or []
        self.shares = shares or []
        self.local_groups = []
        self.domain_groups = []
        self.builtin_groups = []

    def __str__(self):
        return_value = ""
        if self.os_result:
            return_value += "Operating System: {0}\n\n".format(self.os_result.server)

        if self.users:
            return_value += "Users:\n{0}\n\n".format("\n".join([" - {0}".format(str(user)) for user in self.users]))

        if self.shares:
            return_value += "Shares:\n{0}\n\n".format("\n".join([" - {0}".format(str(share)) for share in self.shares]))

        if self.local_groups:
            return_value += "Local groups:\n{0}\n\n".format("\n".join([" - {0}".format(str(group))
                                                                       for group in self.local_groups]))
        if self.domain_groups:
            return_value += "Domain groups:\n{0}\n\n".format("\n".join([" - {0}".format(str(group))
                                                                        for group in self.domain_groups]))
        if self.builtin_groups:
            return_value += "Builtin groups:\n{0}\n\n".format("\n".join([" - {0}".format(str(group))
                                                                         for group in self.builtin_groups]))

        return return_value.strip("\n")


class Enum4linuxOS(object):
    def __init__(self, domain, os, server):
        self.server = server
        self.domain = domain
        self.os = os

    def __str__(self):
        return "OS for {domain} is {os}".format(domain=self.domain, os=self.os)

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
