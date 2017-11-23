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
        return iptc.Rule()

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


# output_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
# input_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
# forward_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "FORWARD")
# rule = iptc.Rule()
# rule.create_target("NFQUEUE")
# output_chain.insert_rule(rule)
# input_chain.insert_rule(rule)
# forward_chain.insert_rule(rule)
# chains = (input_chain, output_chain, forward_chain)
