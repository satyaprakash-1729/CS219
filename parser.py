import numpy as np
import CiscoParser
import pandas as pd
from tqdm import tqdm
from main import Utils

output_path = "stanford_backbone_cons/"
rtr_names = [("bbra_rtr",0),
             ("bbrb_rtr",0),
             ("boza_rtr",0),
             ("bozb_rtr",0),
             ("coza_rtr",580),
             ("cozb_rtr",580),
             ("goza_rtr",0),
             ("gozb_rtr",0),
             ("poza_rtr",0),
             ("pozb_rtr",0),
             ("roza_rtr",0),
             ("rozb_rtr",0),
             ("soza_rtr",580),
             ("sozb_rtr",580),
             ("yoza_rtr",0),
             ("yozb_rtr",0),
             ]
topology = [("bbra_rtr","te7/3","goza_rtr","te2/1"),
            ("bbra_rtr","te7/3","pozb_rtr","te3/1"),
            ("bbra_rtr","te1/3","bozb_rtr","te3/1"),
            ("bbra_rtr","te1/3","yozb_rtr","te2/1"),
            ("bbra_rtr","te1/3","roza_rtr","te2/1"),
            ("bbra_rtr","te1/4","boza_rtr","te2/1"),
            ("bbra_rtr","te1/4","rozb_rtr","te3/1"),
            ("bbra_rtr","te6/1","gozb_rtr","te3/1"),
            ("bbra_rtr","te6/1","cozb_rtr","te3/1"),
            ("bbra_rtr","te6/1","poza_rtr","te2/1"),
            ("bbra_rtr","te6/1","soza_rtr","te2/1"),
            ("bbra_rtr","te7/2","coza_rtr","te2/1"),
            ("bbra_rtr","te7/2","sozb_rtr","te3/1"),
            ("bbra_rtr","te6/3","yoza_rtr","te1/3"),
            ("bbra_rtr","te7/1","bbrb_rtr","te7/1"),
            ("bbrb_rtr","te7/4","yoza_rtr","te7/1"),
            ("bbrb_rtr","te1/1","goza_rtr","te3/1"),
            ("bbrb_rtr","te1/1","pozb_rtr","te2/1"),
            ("bbrb_rtr","te6/3","bozb_rtr","te2/1"),
            ("bbrb_rtr","te6/3","roza_rtr","te3/1"),
            ("bbrb_rtr","te6/3","yozb_rtr","te1/1"),
            ("bbrb_rtr","te1/3","boza_rtr","te3/1"),
            ("bbrb_rtr","te1/3","rozb_rtr","te2/1"),
            ("bbrb_rtr","te7/2","gozb_rtr","te2/1"),
            ("bbrb_rtr","te7/2","cozb_rtr","te2/1"),
            ("bbrb_rtr","te7/2","poza_rtr","te3/1"),
            ("bbrb_rtr","te7/2","soza_rtr","te3/1"),
            ("bbrb_rtr","te6/1","coza_rtr","te3/1"),
            ("bbrb_rtr","te6/1","sozb_rtr","te2/1"),
            ("boza_rtr","te2/3","bozb_rtr","te2/3"),
            ("coza_rtr","te2/3","cozb_rtr","te2/3"),
            ("goza_rtr","te2/3","gozb_rtr","te2/3"),
            ("poza_rtr","te2/3","pozb_rtr","te2/3"),
            ("roza_rtr","te2/3","rozb_rtr","te2/3"),
            ("soza_rtr","te2/3","sozb_rtr","te2/3"),
            ("yoza_rtr","te1/1","yozb_rtr","te1/3"),
            ("yoza_rtr","te1/2","yozb_rtr","te1/2"),
            ]


class Parser:
    def __init__(self):
        self.forwarding_rules = []
        self.acl_rules = []
        self.cs_list = None
        self.topology_data = {}

    def parse_all_files(self):
        f_port = open(output_path+"port_map.txt", "w")
        id = 1
        self.cs_list = {}
        print("Parsing the Router files . . . .")
        for (rtr_name, vlan) in tqdm(rtr_names):
            cs = CiscoParser.cisco_router(id)
            cs.set_replaced_vlan(vlan)
            cs.read_arp_table_file("Stanford_backbone/%s_arp_table.txt" % rtr_name)
            cs.read_mac_table_file("Stanford_backbone/%s_mac_table.txt" % rtr_name)
            cs.read_config_file("Stanford_backbone/%s_config.txt" % rtr_name)
            cs.read_spanning_tree_file("Stanford_backbone/%s_spanning_tree.txt" % rtr_name)
            cs.read_route_file("Stanford_backbone/%s_route.txt" % rtr_name)
            cs.generate_port_ids([])
            # cs.optimize_forwarding_table()
            id += 1
            self.cs_list[rtr_name] = cs

        for (from_router, from_port, to_router, to_port) in topology:
            self.topology_data[(from_router, from_port)] = (to_router, to_port)

        for rtr in self.cs_list.keys():
            cs = self.cs_list[rtr]
            f_port.write("$%s\n" % rtr)
            for p in cs.port_to_id.keys():
                f_port.write("%s:%s\n" % (p, cs.port_to_id[p]))
        f_port.close()

        print("Writing the topology file ....")
        with open(output_path+"topology.csv", "w") as f_topo:
            for (from_router, from_port, to_router, to_port) in tqdm(topology):
                from_cs = self.cs_list[from_router]
                to_cs = self.cs_list[to_router]
                f_topo.write(str(from_cs.get_switch_id()) + ","+str(from_port) +
                             "," + str(to_cs.get_switch_id()) + ","+str(to_port) + "\n")

        print("Writing ID to router map . . . .")
        with open(output_path + "_router_id_map.csv", "w") as f_rtr_id:
            for rtr, cs in tqdm(self.cs_list.items()):
                f_rtr_id.write(str(cs.get_switch_id()) + "," + rtr + "\n")

        print("Writing the ACL files ....")
        for rtr, cs in tqdm(self.cs_list.items()):
            data = []
            for acl_id, acl in cs.acl.items():
                for sub_acl in acl:
                    sub_acl["acl_id"] = acl_id
                    data.append(sub_acl)
            df = pd.DataFrame(data, columns=["acl_id"]+list(list(cs.acl.values())[0][0].keys()))
            df.to_csv(output_path + "acl_" + rtr + ".csv", sep=',', header=True, index=False)

        print("Writing the Forwarding files ....")
        for rtr, cs in tqdm(self.cs_list.items()):
            df = pd.DataFrame(np.array(cs.fwd_table)[:, :3], columns=["prefix", "mask", "port"])
            df.to_csv(output_path + "route_" + rtr + ".csv", index=False)

        self.convert_to_custom_format()

    def parse_and_add_route(self, rtr, df, rtr_id):
        for index, row in df.iterrows():
            ip = Utils.convert_int_to_ip(int(row["prefix"]))
            mask = int(row["mask"])
            port = row["port"].split(".")[0]
            cs = self.cs_list[rtr]
            if (rtr, port) in self.topology_data:
                to_rtr, to_port = self.topology_data[(rtr, port)]
                self.forwarding_rules.append([rtr_id, ip+"/"+str(mask), str(self.cs_list[to_rtr].get_switch_id())])
            elif port.startswith("vlan"):
                ports_spanned = cs.vlan_span_ports[port]
                switch_ids = []
                for port_to_send in ports_spanned:
                    if (rtr, port_to_send) in self.topology_data:
                        to_rtr, to_port = self.topology_data[(rtr, port_to_send)]
                        switch_id = self.cs_list[to_rtr].get_switch_id()
                        switch_ids.append(str(switch_id))
                if len(switch_ids) > 0:
                    self.forwarding_rules.append([rtr_id, ip+"/"+str(mask), "|".join(switch_ids)])

    def convert_to_custom_format(self):
        for rtr in self.cs_list.keys():
            df = pd.read_csv(output_path + "route_" + rtr + ".csv")
            self.parse_and_add_route(rtr, df, self.cs_list[rtr].get_switch_id())

    def write_rules_to_file(self):
        df = pd.DataFrame(self.forwarding_rules, columns=["ID", "prefix", "fwd_to"])
        df.to_csv("routers_created.csv", sep=",", index=False)


parser = Parser()
parser.parse_all_files()
parser.write_rules_to_file()
