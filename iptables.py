import iptc


class IpTables:

    def __init__(self):
        self.table = iptc.Table(iptc.Table.MANGLE)
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

    @staticmethod
    def get_rules(table, chain, num_rules):
        """

        :param table:
        :param chain:
        :param num_rules:
        :return: entries:
        """
        entries = []
        entry = table.first_rule(chain.name)
        rule_num = 0
        while entry and rule_num < num_rules:
            entries.append(entry)
            entry = table.next_rule(entry)
            rule_num += 1
        return [table.create_rule(e, chain) for e in entries]
