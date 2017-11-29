import iptc


class IpTables:

    def __init__(self):
        self.table = iptc.Table(iptc.Table.FILTER)
        self.table.autocommit = False

    def create_chain(self, chain):
        """

        :param chain:
        :return:
        """
        return iptc.Chain(self.table, chain)

    @staticmethod
    def create_rule(destination="127.0.0.1", destination_port=80, protocol="tcp"):
        """

        :return:
        """
        rule = iptc.Rule()
        rule.dst = destination
        rule.protocol = protocol
        match = rule.create_match(protocol)
        match.dport = str(destination_port)
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

