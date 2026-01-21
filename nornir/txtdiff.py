import re
ld6_lines = []
scc_lines = []
ld6_lines_not_in_scc = []
scc_lines_not_in_ld6 = []
with open("uk-ld6-fw04.txt") as search:
    for line in search:
        line = line.rstrip()  # remove '\n' at end of line
        line = re.sub("-ld6-","",line)
        ld6_lines.append(line)



with open("uk-sc1-fw04.txt") as search:
    for line in search:
        line = line.rstrip()  # remove '\n' at end of line
        line = re.sub("-sc1-","",line)
        scc_lines.append(line)

print("LD6:")
print(str(len(ld6_lines))+" lines found")
print("SCC:")
print(str(len(scc_lines))+" lines found")


for row in scc_lines:
    if row not in ld6_lines :
        scc_lines_not_in_ld6.append(row)

for row in ld6_lines:
    if row not in scc_lines :
        ld6_lines_not_in_scc.append(row)

print("SCC config not in LD6:")
print(str(len(scc_lines_not_in_ld6))+" lines found")
print("LD6 config not in SCC:")
print(str(len(ld6_lines_not_in_scc))+" lines found")

with open('scc_lines_not_in_ld6.txt', 'w') as f:
    for line in scc_lines_not_in_ld6:
        f.write(line)
        f.write("\n")
with open('ld6_lines_not_in_scc.txt', 'w') as f:
    for line in ld6_lines_not_in_scc:
        f.write(line)
        f.write("\n")