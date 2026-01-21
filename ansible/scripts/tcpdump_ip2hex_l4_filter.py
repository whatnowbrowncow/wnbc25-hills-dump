import ipaddress

def main():
	print("\nPlease enter filter info. Press enter for default values: \n")
	src_ip = src_ip_prompt()
	dst_ip = dst_ip_prompt()
	dst_port = dst_port_prompt()
	src_ip_hex = ip_2_hex(src_ip)
	dst_ip_hex = ip_2_hex(dst_ip)
	dst_tcp_hex = tcp_2_hex(dst_port)
	result = generate(src_ip,dst_ip,dst_port,src_ip_hex,dst_ip_hex,dst_tcp_hex)

def src_ip_prompt():
	while True:
		try:
			src_ip = input("> src ip [any]: ") or "any"
			if not (src_ip == "any"):
				ipaddress.ip_address(src_ip)
		except ValueError:
			print('\nInvalid input, please try again\n')
			continue
		else:
			return src_ip


def dst_ip_prompt():
	while True:
		try:
			dst_ip = input("> dst ip [any]: ") or "any"
			if not (dst_ip == "any"):
				ipaddress.ip_address(dst_ip)
		except ValueError:
			print('\nInvalid input, please try again\n')
			continue
		else:
			return dst_ip

def dst_port_prompt():
	while True:
		try:
			dst_port = (input("> dst port [any]: ")) or "any"
			if not dst_port == "any":
				int(dst_port)
				return int(dst_port)
		except ValueError:	
			print("\nInvalid input, please try again\n")
			continue
		else:
			return dst_port

def ip_2_hex(ip):
	if not (ip == "any"):
		ip_hex = "0x" + "".join(map(lambda i: "{:02X}".format(int(i)), ip.split(".")))
		return ip_hex
	else:
		ip_hex = "any"
		return ip_hex

def tcp_2_hex(port):
	if not (port == "any"):		
		tcp_hex = hex(port)
		return tcp_hex
	else:
		tcp_hex = "any"
		return tcp_hex


def generate(src_ip,dst_ip,dst_port,src_ip_hex,dst_ip_hex,dst_tcp_hex):
	tcpdump_all = "sudo tcpdump -ni ens192 'proto gre'"
	tcpdump_filtered = "sudo tcpdump -ni ens192 'proto gre"
	if src_ip_hex != "any" and dst_ip_hex != "any" and dst_tcp_hex != "any":
		print("\nThe following command will filter traffic between {} and {} on TCP/{}:\n".format(src_ip,dst_ip,dst_port))
		print("{} and ((ip[54:4]={} and ip[58:4]={})) or ((ip[54:4]={} and ip[58:4]={})) and ((ip[64:2]={}))'\n".format(tcpdump_filtered,src_ip_hex,dst_ip_hex,dst_ip_hex,src_ip_hex,dst_tcp_hex))
	elif src_ip_hex != "any" and dst_ip_hex == "any" and dst_tcp_hex != "any":
		print("\nThe following command will filter traffic from {} on TCP/{}:\n".format(src_ip,dst_port))
		print("{} and ((ip[54:4]={})) or ((ip[58:4]={})) and ((ip[64:2]={}))'\n".format(tcpdump_filtered,src_ip_hex,src_ip_hex,dst_tcp_hex))
	elif src_ip_hex == "any" and dst_ip_hex != "any" and dst_tcp_hex != "any":
		print("\nThe following command will filter traffic to {} on TCP/{}:\n".format(dst_ip,dst_port))
		print("{} and ((ip[58:4]={})) or ((ip[54:4]={})) and ((ip[64:2]={}))'\n".format(tcpdump_filtered,dst_ip_hex,dst_ip_hex,dst_tcp_hex))
	elif src_ip_hex != "any" and dst_ip_hex == "any":
		print("\nThe following command will filter all GRE encapsulated traffic from {}:\n".format(src_ip))
		print("{} and ((ip[54:4]={})) or ((ip[58:4]={}))'\n".format(tcpdump_filtered,src_ip_hex,src_ip_hex))
	elif src_ip_hex == "any" and dst_ip_hex != "any":
		print("\nThe following command will filter all GRE encapsulated traffic to {}:\n".format(dst_ip))
		print("{} and ((ip[58:4]={})) or ((ip[54:4]={}))'\n".format(tcpdump_filtered,dst_ip_hex,dst_ip_hex))
	elif src_ip_hex == "any" and dst_ip_hex == "any" and dst_tcp_hex != "any":
		print("\nThe following command will filter all GRE encapsulated traffic on TCP/{}:\n".format(dst_port))
		print("{} and ((ip[64:2]={}))'\n".format(tcpdump_filtered,dst_tcp_hex))			
	else:
		print("\nThe following command will filter all GRE encapsulated traffic:\n")
		print((tcpdump_all),"\n")
 

if __name__ == '__main__':
	main()

