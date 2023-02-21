import os
import sys

def add_rule_to_etc_hosts(ip, url, hosts_path):
    with open(hosts_path, 'r') as hosts:
        lines = hosts.readlines()
        host_exist = False
        # 存在就修改
        for index, line in enumerate(lines):
            if url in line:
                ips = line.split()
                ips[0] = ip
                lines[index] = " ".join(ips) + "\n"
                host_exist = True
                break
        # 不存在则新增
        if not host_exist:
            ips = "{} {}\n".format(ip, url)
            lines.append(ips)

    with open(hosts_path, 'w') as hosts:
        hosts.writelines(lines)

if __name__== "__main__" :
    if len(sys.argv) < 4:
        print("argv:{}. less then 4 argument, "
              "python add_rule_to_etc_hosts.py ip url etc_hosts_path".format(sys.argv))
    else:
        ip = sys.argv[1]
        url = sys.argv[2]
        url = url.replace()
        hosts_path = sys.argv[3]
        add_rule_to_etc_hosts(ip, url, hosts_path)