from z3 import *
import argparse
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt


class BinaryTrie:
    def __init__(self):
        self.isLeaf = False
        self.children = {0: None, 1: None}
        self.rule_number = None
        self.negations = []

    def add_prefix(self, rule, prefix):
        if prefix == "":
            self.isLeaf = True
            self.rule_number = rule.rule_number
            return
        if self.isLeaf:
            self.negations.append(rule.rule_number)
        node = int(prefix[0])
        if self.children[node] is None:
            self.children[node] = BinaryTrie()
        self.children[node].add_prefix(rule, prefix[1:])


class Rule:
    def __init__(self, rule_number, prefix, forward_id):
        self.rule_number = rule_number
        self.prefix = prefix
        self.forwarded_to = forward_id


class Utils:
    @staticmethod
    def get_prefix_with_mask(cidr):
        if "/" in cidr:
            address, mask = cidr.split('/')
            octets = map(int, address.split('.'))
            binary = '{0:08b}{1:08b}{2:08b}{3:08b}'.format(*octets)
            mask = int(mask)
            return binary[:mask]
        else:
            octets = map(int, cidr.split('.'))
            binary = '{0:08b}{1:08b}{2:08b}{3:08b}'.format(*octets)
            return binary

    @staticmethod
    def convert_prefix_to_boolean_expr(x, prefix):
        total_length = 32
        residual = total_length - len(prefix)
        starting = prefix + "0" * residual
        ending = prefix + "1" * residual
        return And(x >= int(starting, 2), x <= int(ending, 2))

    @staticmethod
    def convert_int_to_ip(num):
        binary_form = '{0:32b}'.format(num)
        first = int(binary_form[:8], 2)
        second = int(binary_form[8:16], 2)
        third = int(binary_form[16:24], 2)
        fourth = int(binary_form[24:32], 2)
        return str(first) + "." + str(second) + "." + str(third) + "." + str(fourth)

    @staticmethod
    def parse_input_data(df, verbose=False):
        router_list = {}
        router_temp_list = {}
        rule_list = []
        rule_number = 0
        edge_list = {}
        cidr_list = {}
        print("Creating Routers....")
        for i in range(len(df)):
            rid = int(df.iloc[i, 0])
            cidr = df.iloc[i, 1]
            fid = int(df.iloc[i, 2])
            cidr_list[(rid, fid)] = cidr
            prefix = Utils.get_prefix_with_mask(cidr)
            if rid not in router_list:
                router_list[rid] = Router(rid)
                router_temp_list[rid] = []
            if fid not in router_list:
                router_list[fid] = Router(fid)
                router_temp_list[fid] = []
            if rid not in edge_list:
                edge_list[rid] = [(fid, prefix+"*")]
            else:
                edge_list[rid].append((fid, prefix+"*"))
            router_temp_list[rid].append((prefix, rule_number))
            rule_list.append(Rule(rule_number, prefix, fid))
            rule_number += 1

        for rid, rule in router_temp_list.items():
            router_temp_list[rid].sort(key=lambda x: len(x[0]))
            rules = [rule_list[rule[1]] for rule in router_temp_list[rid]]
            router_list[rid].add_all_rules(rules)
            router_list[rid].populate_policies(router_list[rid].rule_book, rule_list)
            router_list[rid].parse_policies(rule_list)

        if verbose:
            print(">>> Number of routers: ", len(router_list.keys()))
            graph = nx.Graph()

            graph.add_nodes_from(router_list.keys())
            label_nodes = {}
            for k, _ in router_list.items():
                label_nodes[k] = k
            edges = []
            for src in edge_list.keys():
                for dst in edge_list[src]:
                    graph.add_edge(src, dst[0])
                    edges.append((src, dst[0]))
            pos = nx.spring_layout(graph)
            nx.draw_networkx_nodes(graph, pos, router_list.keys())
            nx.draw_networkx_edges(graph, pos, edges, arrowstyle="->", arrowsize=10, width=2)
            nx.draw_networkx_edge_labels(graph, pos, cidr_list)
            nx.draw_networkx_labels(graph, pos, label_nodes)
            plt.show()

        return router_list, rule_list


class Router:
    def __init__(self, router_id):
        self.router_id = router_id
        self.rule_book = BinaryTrie()
        self.done_adding = False
        self.policies = None

    def add_rule(self, rule):
        self.rule_book.add_prefix(rule, prefix=rule.prefix)

    def add_all_rules(self, rule_list):
        for rule in rule_list:
            self.add_rule(rule)
        self.done_adding = True

    def populate_policies(self, node, rule_list):
        if node.isLeaf:
            rule = rule_list[node.rule_number]
            if self.policies is not None:
                self.policies.append((rule, node.negations))
            else:
                self.policies = [(rule, node.negations)]
        if node.children[0] is not None:
            self.populate_policies(node.children[0], rule_list)
        if node.children[1] is not None:
            self.populate_policies(node.children[1], rule_list)

    def parse_policies(self, rule_list):
        if not self.done_adding or self.policies is None:
            return
        for i in range(len(self.policies)):
            rule = self.policies[i][0]
            negations = self.policies[i][1]
            x = Int('x')
            parsed = Utils.convert_prefix_to_boolean_expr(x, rule.prefix)
            for neg in negations:
                parsed = And(parsed, Not(Utils.convert_prefix_to_boolean_expr(x, rule_list[neg].prefix)))
            self.policies[i] = (parsed, rule.forwarded_to)


class AntEater:
    def __init__(self, router_list, rule_list):
        self.router_list = router_list
        self.rule_list = rule_list

    def check_reachability(self, s, t, k):
        dp = [[False for i in range(k+1)] for j in range(len(self.router_list.keys())+1)]
        dp[t][0] = True
        for i in range(1, k+1):
            for rid, rt in self.router_list.items():
                if rid != t and rt.policies is not None:
                    for policy in rt.policies:
                        dp[rid][i] = Or(dp[rid][i], And(policy[0], dp[policy[1]][i-1]))
        final_rule = dp[s][1]
        for i in range(2, k+1):
            final_rule = Or(final_rule, dp[s][i])
        final_rule = And(final_rule, Int('x') > 0)
        final_rule = And(final_rule, Int('x') < 2 ** 32)
        return final_rule

    def loop_detection(self):
        final_rule = False
        for vertex in self.router_list.keys():
            max_router_id = max(self.router_list.keys())
            new_router_id = max_router_id+1
            self.router_list[new_router_id] = Router(new_router_id)
            added_list = []
            for rid, router in self.router_list.items():
                if router.policies is not None:
                    for policy, fid in router.policies:
                        if fid == vertex:
                            router.policies.append((policy, new_router_id))
                            added_list.append(router.policies)
            final_rule = Or(final_rule, self.check_reachability(vertex, new_router_id, len(self.router_list.keys())-1))
            del self.router_list[new_router_id]
            for added in added_list:
                added.pop()
        final_rule = And(final_rule, Int('x') > 0)
        final_rule = And(final_rule, Int('x') < 2 ** 32)
        return final_rule

    def packet_loss(self, vertex, destinations):
        routers = self.router_list.keys()
        num_routers = len(routers)
        max_router_id = max(routers)
        new_router_id = max_router_id + 1
        self.router_list[new_router_id] = Router(new_router_id)
        for rid in destinations:
            router = self.router_list[rid]
            if router.policies is not None:
                router.policies.append((True, new_router_id))
            else:
                router.policies = [(True, new_router_id)]
        final_rule = Not(self.check_reachability(vertex, new_router_id, num_routers))
        del self.router_list[new_router_id]
        for rid in destinations:
            self.router_list[rid].policies.pop()
        final_rule = And(final_rule, Int('x') > 0)
        final_rule = And(final_rule, Int('x') < 2**32)
        return final_rule


class TestSuite:
    @staticmethod
    def test_reachability(anteater):
        print("Enter Source Router ID: ")
        s = int(input())
        print("Enter Target Router ID: ")
        t = int(input())
        expr = anteater.check_reachability(s, t, len(anteater.router_list.keys()) - 1)
        print("----------------------------------")

        print("\n\nThe final SAT Expression for reachability: ", expr)
        print("\n---------------------------------\n")
        solver = Solver()
        solver.add(expr)
        print("Solution: ")
        if solver.check().r != -1:
            m = solver.model()
            for var in m.decls():
                print(">>>> IP: ", Utils.convert_int_to_ip(m[var].as_long()))
        else:
            print("No Solution...")

    @staticmethod
    def test_loops(anteater):
        expr = anteater.loop_detection()
        print("\n\nThe final SAT Expression for loops: ", expr)
        print("\n--------------------------------\n")
        solver = Solver()
        solver.add(expr)
        if solver.check().r != -1:
            print("Loop found!...")
            m = solver.model()
            for var in m.decls():
                print(">>>> IP: ", Utils.convert_int_to_ip(m[var].as_long()))
            return
        print("No Loops Found !")

    @staticmethod
    def test_packet_loss(anteater):
        print("Enter Source Router ID: ")
        src = int(input())
        print("Enter Destination Set Router IDs (separated by spaces):")
        dst = list(map(int, input().strip().split()))
        if src in dst:
            raise ValueError("Invalid input. Source exists in destination set.")
        expr = anteater.packet_loss(src, dst)
        print("\n\nThe final SAT Expression for Packet Loss: ", expr)
        print("\n-------------------------------\n")
        solver = Solver()
        solver.add(expr)
        if solver.check().r != -1:
            print("Packet Loss Detected!...\nFollowing header is for one of the lost packets->")
            m = solver.model()
            for var in m.decls():
                print(">>>> IP: ", Utils.convert_int_to_ip(m[var].as_long()))
            return
        print("No Packet Loss!")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--router_file', help="Router List File", action='store', required=True)
    parser.add_argument('-t', '--test_id', help="1: reachability 2: loop 3: packet loss", action='store', required=True)
    parser.add_argument('-n', '--draw_network', help="Network display toggle", action='store_true')
    args = parser.parse_args()
    print("Reading network flow file . . .")
    df = pd.read_csv(args.router_file)

    router_list, rule_list = Utils.parse_input_data(df, args.draw_network)
    anteater = AntEater(router_list, rule_list)

    print("-----------------------------")
    if int(args.test_id) == 1:
        print("\n\nReachability Test . . . . ")
        TestSuite.test_reachability(anteater)
    elif int(args.test_id) == 2:
        print("\n\nLoops Test . . . .")
        TestSuite.test_loops(anteater)
    elif int(args.test_id) == 3:
        print("\n\nPacket Loss Test . . . .")
        TestSuite.test_packet_loss(anteater)
    else:
        print("Please choose a correct Test ID\n1 --> Reachability\n2 --> Loop Detection\n3 --> Packet Loss Detection")


if __name__ == "__main__":
    main()
