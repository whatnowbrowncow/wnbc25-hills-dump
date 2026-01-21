import ipaddress

datafile = open("/gitnet/ansible/script-outputs/dev/ld6-epgs/ld6-epg-query-data.txt", "r")


def main():
    for aline in datafile:
        print(f'aline = {aline}')
        values = aline.split('\'')
        print(values)

        dn = values[7]
        print(dn)

        dn_list = dn.split("/")
        print(dn_list)

        tenant = dn_list[1].replace("tn-", "")
        print(tenant)

        if tenant == "PTE":
            app_prof = dn_list[2].replace("ap-", "")
            # print(app_prof)

            if app_prof == "PTE-Offshore":
                vrf = "PTE-Offshore"
            elif app_prof == "PTE-Onshore":
                vrf = "PTE-Onshore"
            else:
                vrf = "PTE-internal-vrf"

            epg = dn_list[-1].replace("epg-", "")
            print(epg)

            name_start = epg.split("-")
            del (name_start[-1])
            name_start = "-".join(name_start)
            # print(name_start)

            ip_addr = epg.split("-")[-1]
            # print(ip_addr)

            ip_addr_improved = ip_addr.replace("s", "/")
            # print(ip_addr_improved)
            try:
                mask = ipaddress.ip_network(ip_addr_improved).netmask
                # print(mask)
            except ValueError as err:
                print(f'ERROR for EGP: {epg} :: {err}')
                pass

            try:
                ipaddress.ip_network(ip_addr_improved)
            except ValueError:
                print(f'{ip_addr} converts to: {ip_addr_improved} and this is not a valid IP address!')
                pass
            else:
                print("PARSED OK")
                net_addr, cidr = ip_addr.split("s")
                # print(net_addr)
                # print(cidr)

                gw = ipaddress.ip_network(ip_addr_improved)[1]
                # print(gw)

                dev4File = open("/gitnet/ansible/script-outputs/dev/ld6-epgs/epg_query_parser_output.yml", "a")
                dev4File.write(f'''
  - app_prof: "{app_prof}"
    tenant: "{tenant}"
    vrf: "{vrf}"
    bds:
      - bd: "{name_start}"
        network: "{net_addr}"
        gateway: "{gw}"
        mask: "{mask}"
        cidr_mask: "{cidr}"
        scope: "shared"
        l3_ownership: firewall
        epgs:
          - epg: "{name_start}"
            vcenter_dynamic_vlan: true
''')
                dev4File.close()
        else:
            pass


if __name__ == '__main__':
    main()
