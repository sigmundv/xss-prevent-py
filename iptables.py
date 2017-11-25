import iptc


class IpTables:

    def __init__(self):
        self.table = iptc.Table(iptc.Table.FILTER)

    def create_chain(self, chain):
        """

        :param chain:
        :return:
        """
        return iptc.Chain(self.table, chain)

    @staticmethod
    def create_rule():
        """

        :return:
        """
        rule = iptc.Rule()
        rule.protocol = "tcp"
        match = rule.create_match("tcp")
        match.dport = "80"
        return rule

    @staticmethod
    def create_target(rule, target):
        """

        :param rule:
        :param target:
        :return:
        """
        rule.create_target(target)

    @staticmethod
    def insert_rule(chain, rule):
        """

        :param chain:
        :param rule:
        :return:
        """
        chain.insert_rule(rule)

    @staticmethod
    def delete_rule(chain, rule):
        """

        :param chain:
        :param rule:
        :return:
        """
        chain.delete_rule(rule)

