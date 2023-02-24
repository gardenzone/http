# coding=gbk
import openpyxl
from yaml import load, FullLoader
import sys
import json
import math
import time
from json import JSONDecodeError
import urllib3
import requests
import os

# ���ò���
# ÿ�� case ���Ĵ���� excel ������
max_modify_step = 10

# ��ȡ excel �ļ�������ɸѡ�������
def read_dpi_config(file_path, data_select_num):
    default_file = file_path
    default_sheet_name = '���α��'
    title = {
        'flag': '�����־',
        'description': '���˵��',
        'code': 'ҵ�����',
        'name': 'ҵ������',
        'l3': '����Ŀ��IP��ַ',
        'protocol': 'Э���',
        'l4': '�Ĳ�Ŀ�Ķ˿ں�',
        'l7': '�߲�URL',
    }
    select_num = data_select_num

    file_path = default_file
    sheet_name = default_sheet_name
    # �� excel �ļ�
    wb = openpyxl.load_workbook(file_path, data_only=True)
    sheet = wb[sheet_name]
    row_count = sheet.max_row
    col_count = sheet.max_column

    def get_one_row(sheet, row_num, discard_none=False):
        col_count = sheet.max_column
        if discard_none:
            result = [sheet.cell(row_num, i).value for i in range(1, col_count + 1) if
                      sheet.cell(row_num, i).value != None]
        else:
            result = [sheet.cell(row_num, i).value for i in range(1, col_count + 1)]
        return result

    def init_title_col(title_list):
        for key, value in title.items():
            if value in title_list:
                title[key] = title_list.index(value) + 1

    # ��ȡ��ͷ���ݣ���ʼ���б�ͷ���ݵ����±�
    title_values1 = get_one_row(sheet, 1)
    title_values2 = get_one_row(sheet, 2)
    init_title_col(title_values1)
    init_title_col(title_values2)

    # print(title)

    # ��ÿ�����ݽ��з���
    def rule_type(title_values, row_num):
        # layer = ['l3', 'l4', 'l7', 'protocol']
        layer = ['l3', 'l7']
        key_list = []

        # l3, l4, l7, protocol
        for key in layer:
            value = title_values.get(key)
            if value != None and value != "":
                key_list.append(key)
        # # http/https
        # if title_values.get('l7') != None:
        #     if 'https://' in title_values.get('l7'):
        #         key_list.append('https')
        #     else:
        #         key_list.append('http')

        type_str = "+".join(key_list)
        return type_str

        # ��ÿһ�����ݽ��з���

    rule_types = {}
    for row_num in range(3, row_count):
        row_value = {'line_num': row_num}
        for name, col in title.items():
            row_value[name] = sheet.cell(row_num, col).value
        # ֻѡ������־Ϊ���������Ĺ��򣬡�ɾ�����Ĺ�����Ҫ����
        if row_value['flag'] != '����':
            continue
        type_str = rule_type(row_value, row_num)

        code = row_value['code']
        if code not in rule_types:
            rule_types[code] = {}
        if type_str not in rule_types[code]:
            rule_types[code][type_str] = []
        rule_types[code][type_str].append(row_value)

    def mask_sort(line):
        ip_mask = line['l3']
        # ����ѡΨһ��ַ�����ѡ ip ��Χ��С��
        if "/" not in ip_mask:
            return 0
        mask = int(ip_mask.split('/')[1])
        # ipv6
        if mask > 32:
            return 128 - mask
        # ipv4
        else:
            return 32 - mask

    def url_sort(line):
        # ����ѡ * ���ٵģ����ѡ * �ں����
        url = line['l7']
        star_num = url.count("*")
        if star_num == 0:
            return 0
        elif star_num == 1:
            if url[-1] == "*":
                return 2
            else:
                return 1
        else:
            return 3

    # ������Ƶ����ȼ���ÿ�����ݽ������򣬳�ȡ���ȼ���ߵļ�������
    def case_choice(type_str, type_list):
        if len(type_list) < select_num:
            return type_str, type_list
        sort_list = []
        # ����
        if 'l3' in type_str and 'l7' in type_str:
            sort_list = sorted(type_list, key=lambda line: (mask_sort(line), url_sort((line))))
        elif 'l3' in type_str:
            sort_list = sorted(type_list, key=mask_sort)
        elif 'l7' in type_str:
            sort_list = sorted(type_list, key=url_sort)
        # ��ȡ�������ݷ���
        result = sort_list[:select_num]
        # result = sort_list
        return type_str, result

    # ����ͬҵ����룬������������ͬ�����ݺϲ���һ��
    case_select = {}
    for code, types in rule_types.items():
        for type_str, tpye_list in types.items():
            t_str, selects = case_choice(type_str, tpye_list)
            if t_str not in case_select:
                case_select[t_str] = []
            case_select[t_str].extend(selects)
    return case_select


class AAT_API:

    # resource name
    epg_resource = 'epg'
    apn_resource = 'apn'
    https_resource = 'httpserver-sut'
    create_https_resource_prefix = 'aat-dpi-http'
    # test step �� name
    imsi_attach_step_name = '(L) IMSI Attach'
    http_step_name = '(L) Initial HTTP Service'
    https_step_name = 'HTTP(S)_Service'
    ue_detach_step_name = '(L) UE Initiated Detach'
    linux_command_step_name = 'Linux_Command'
    epg_command_step_name = 'Appointed_Command_of_EPG'

    def __init__(self, aat_domain, user_name, password):
        self.aat_domain = aat_domain
        self.user_name = user_name
        self.password = password
        # ȡ�� https �ĸ澯
        urllib3.disable_warnings()
        # ��ʼ�� api key
        self.api_key = None
        self.get_api_key()
        self.server_id = self.get_epcft_service_id()

    def _common_request(self, method, url, params=None, json=None, headers=None, data=None):
        if not headers:
            headers = {
                "Content_Type": "application/json",
                "apikey": self.api_key,
            }
        else:
            headers["apikey"] = self.api_key
        url = "{}/{}".format(self.aat_domain, url)
        args = {
            "params": params,
            "json": json,
            "headers": headers,
            "data": data,
        }
        response = requests.request(method, url, **args, verify=False, timeout=10)
        status_code = response.status_code
        if status_code >= 400:
            print('url', url)
            print('response.text', response.text)
            raise Exception
        if response.content:
            try:
                return status_code, response.json()
            except JSONDecodeError:
                # print('url', url)
                return status_code, response.text
        return status_code, ''

    def get(self, url, params=None, headers=None):
        return self._common_request("GET", url, params=params, headers=headers)

    def post(self, url, body=None, headers=None, data=None):
        return self._common_request("POST", url, json=body, headers=headers, data=data)

    def delete(self, url, params=None, headers=None):
        return self._common_request("DELETE", url, params=params, headers=headers)

    def get_api_key(self):
        name = self.user_name
        password = self.password
        # ��ȡ api ����Ȩ��
        url = "/api/aat/apikey?username={}&password={}".format(name, password)
        _, response = self.get(url)
        # print('get_api_key response', response)
        api_key = response['result']['apiKey'][0]
        self.server_id = None
        self.api_key = api_key
        return api_key

    def get_test_services(self):
        # ��ȡ���� test service ��Ϣ
        url = "/api/aat/v1/service"
        _, response = self.get(url)
        # print('get_test_services', response)
        return response['result']

    def get_epcft_service_id(self):
        # ��ȡ test service �� epc ft ����Ϣ
        services = self.get_test_services()
        for service_id, value in services.items():
            if 'EPC' in value['serviceName'] and "function test" in value['serviceType']:
                return service_id

    def get_service_test_case(self, service_id):
        url = "/api/aat/v1/{}/test_case".format(service_id)
        _, response = self.get(url)
        return response['result']['data']

    def get_test_case_id(self, service_id, case_name):
        cases = self.get_service_test_case(service_id)
        for case in cases:
            if case_name == case['name']:
                return case['id']
        print("not exist case name:{} in service {}".format(case_name, service_id))
        return

    def get_test_case_by_id(self, service_id, case_id):
        url = "/api/aat/v1/{}/test_case/{}".format(service_id, case_id)
        _, response = self.get(url)
        return response['result']

    def change_test_case_by_id(self, service_id, case_id, change_data):
        url = "/api/aat/v1/{}/test_case/{}".format(service_id, case_id)
        if 'labels' not in change_data:
            change_data['labels'] = []
        self.post(url, change_data)

    def get_resource(self, service_id, type_name):
        # resource_name ���� resource �� type
        url = "/frontend/{}/resource/{}".format(service_id, type_name)
        _, response = self.get(url)
        return response['result']

    def get_resource_by_name(self, service_id, type_name, resource_name):
        resources = self.get_resource(service_id, type_name)
        # print(resources)
        for resource in resources:
            name = resource['data']['name']
            if name == resource_name:
                return resource
        print("not exist resource name:{} in {} type".format(resource_name, type_name))

    def get_resource_by_id(self, service_id, type_name, resource_id):
        url = "/frontend/{}/resource/{}/{}".format(service_id, type_name, resource_id)
        _, response = self.get(url)
        return response['result']

    def change_resource_by_id(self, service_id, type_name, resource_id, change_data):
        url = "/frontend/{}/resource/{}/{}".format(service_id, type_name, resource_id)
        if change_data['description'] == '':
            change_data['description'] = type_name
        _, response = self.post(url, change_data)
        return resource_id

    def create_resource(self, service_id, type_name, data):
        url = "/frontend/{}/resource/{}".format(service_id, type_name)
        _, response = self.post(url, data)
        # resource id
        return response["result"]["id"]

    def create_or_update_resource(self, service_id, type_name, data):
        # ������ڶ�Ӧ�� resource name������� resource�����򴴽� resource
        resource = self.get_resource_by_name(service_id, type_name, data['name'])
        if resource:
            resource_id = self.change_resource_by_id(service_id, type_name, resource['id'], data)
        else:
            resource_id = self.create_resource(service_id, type_name, data)
        return resource_id

    def remove_resource_by_name(self, service_id, type_name, resource_name):
        resource = self.get_resource_by_name(service_id, type_name, resource_name)
        # ���ھ�ɾ��
        if resource:
            resource_id = resource['id']
            url = "/frontend/{}/resource/{}/{}".format(service_id, type_name, resource_id)
            _, response = self.delete(url)

    def start_test_case_execution(self, service_id, case_id):
        url = "/api/aat/v1/{}/test_execution".format(service_id)
        body = {
            "type": "testcase",
            "id": case_id,
        }
        _, response = self.post(url, body)
        # task id
        return response["result"]["id"]

    def get_test_execution_status_by_id(self, service_id, task_id):
        url = "/api/aat/v1/{}/test_execution?id={}".format(service_id, task_id)
        _, response = self.get(url)
        return response['result']['data']

    def get_test_execution_log_id(self, service_id, task_id, case_id):
        case_done = False
        data = {}
        while not case_done:
            data = self.get_test_execution_status_by_id(service_id, task_id)
            print('case is running, please waiting ...')
            if data.get('endedTime') is None:
                time.sleep(10)
            else:
                case_done = True

        cases = data['testCaseList']
        for case in cases:
            if case_id in [case.get('testcase_id'), case.get('testcaseId')]:
                logs = filter(lambda log: 'Log' in log['name'], case['logs'])
                return list(logs)[0]['id']

    def get_test_case_log(self, service_id, log_id):
        url = "/api/aat/v1/{}/logs/{}?type=text".format(service_id, log_id)
        _, response = self.get(url)
        return response

    def import_test_case(self, service_id, tar_path):
        url = "/frontend/{}/import".format(service_id)
        with open(tar_path, "rb") as tar:
            data_binary = tar.read()
        self.post(url, data=data_binary)
        pass

    def export_test_case(self, service_id):
        url = "/frontend/{}/export".format(service_id)


def get_domain_name(url):
    return url.split("://")[1].split("/")[0].split(":")[0]

def url_completion(line):
    url = line['l7']
    if url == "":
        return url

    url = url.replace("//*.", "//www.")
    url = url.replace("//*", "//www.")
    if 'http://' in url:
        # http * ����β���򣬲��� index
        # http * ����β����ɾ�� *
        url = url.replace("/*", "/")
        #
        url = url.replace(":*.", ":80")
    else:
        url = url.replace("/*", "/")
        url = url.replace(":*.", ":443")
    # ���ָ���˶˿ں����� url ����Ӷ˿ں�
    if line['l4'] != "" and line['l4'] is not None:
        url = url.replace(".com", ".com:{}".format(line['l4']))
    # print(line['l7'], url)
    return url

def ip_completion(line):
    ip_mask = line.get('l3')
    if not ip_mask:
        return None
    if "/" not in ip_mask:
        return ip_mask
    ip, mask = ip_mask.split('/')
    # IPV6��ʡ��ȫ0
    ipv6_colon = ip.count(":")
    ip = ip.replace('::', ':0000' * (8-ipv6_colon) + ':')
    # Ψһ��ַ
    if mask == '32' or mask == '128':
        line['l3'] = ip
    else:
        # ѡ��һ����Ч��ַ��ΪĿ��IP
        ip = ip.split('.')
        mask = int(mask)
        mask_range = int(mask/8)
        mask_last = int(mask%8)
        ip[mask_range] = str(int(ip[mask_range]) & (256 - int(math.pow(2, 8-mask_last)))) + 1
        ip = ".".join(ip)
    return ip


def repalce_resource(steps_object, type, old, new):
    step_str = json.dumps(steps_object)
    old_str = '''"type": "{}", "value": "{}"'''.format(type, old)
    new_str = '''"type": "{}", "value": "{}"'''.format(type, new)
    step_str = step_str.replace(old_str, new_str)
    steps_object = json.loads(step_str)
    return steps_object


def change_case_epg_and_apn(aat, server_id, steps, config_yaml):
    config_epg_name = config_yaml.get('epg_name')
    epg_with_apn = config_yaml.get('epg_with_apn')
    epg_step = get_test_step_by_name(steps, AAT_API.epg_command_step_name)
    if epg_step:
        step_epg_id = epg_step['parameters']['Target']['value']
        step_epg_name = aat.get_resource_by_id(server_id, aat.epg_resource, step_epg_id)['name']
    else:
        # ��� case û�� epg step ����Ҫ�޸� apn �� epg ����Ϣ
        return steps

    # ����û�ָ���� epg������ epg �����ֺ� case ģ��ʹ�õ� epg ���ֲ�ͬ
    if config_epg_name not in ['', None] and config_epg_name != step_epg_name:
        epg_id = aat.get_resource_by_name(server_id, AAT_API.epg_resource, config_epg_name)['id']
        apn_id = aat.get_resource_by_name(server_id, AAT_API.apn_resource, epg_with_apn[config_epg_name])['id']
        # �޸� case �е� epg �� apn ������
        for step in steps:
            name = step.get('name')
            if step.get('parameters') and 'APN' in step['parameters']:
                step['parameters']['APN']['value'] = apn_id
            if name == aat.epg_command_step_name:
                step['parameters']['Target']['value'] = epg_id

    return steps

def change_https_step_https_resource(aat, server_id, steps, lines):
    index = 0
    for step in steps:
        name = step.get('name')
        if name == AAT_API.https_step_name:
            resource_name = "{}{}".format(AAT_API.create_https_resource_prefix, index)
            if lines[index].get('l3') and not lines[index].get('l7'):
                # �� ip ��û url, l3 �� case, host_name Ϊ ip
                node_type = 'HTTP'
                host_name = ip_completion(lines[index])
            else:
                # ���� l7 �� case
                url = url_completion(lines[index])
                node_type = url.split("://")[0].upper()
                host_name = get_domain_name(url)

            # Ĭ�� 80 �˿�
            port = 80
            # https �� l7 ��Ҫ���˿ڸ�Ϊ 443
            if node_type == 'HTTPS':
                port = 443
            # ���ָ���˿ڣ���ʹ��ָ���˿�
            if lines[index].get('l4') not in ['', None]:
                port = int(lines[index].get('l4'))
            https_resource_data = {
                '_version': '_removed_intentionally_',
                'HostName': host_name,
                'name': resource_name,
                'Port': port,
                'NodeType': node_type,
                'description': resource_name,
            }
            resource_id = aat.create_or_update_resource(server_id, AAT_API.https_resource, https_resource_data)
            step['destination']['value'] = resource_id
            index += 1
    return steps

def remove_https_resource(aat, server_id):
    for index in range(max_modify_step):
        https_resource_name = "{}{}".format(AAT_API.create_https_resource_prefix, index)
        aat.remove_resource_by_name(server_id, AAT_API.https_resource, https_resource_name)

def change_http_step_url(steps, lines):
    index = 0
    for step in steps:
        name = step.get('name')
        if name == AAT_API.http_step_name:
            url = url_completion(lines[index])
            step['parameters']['URL']['value'] = url
            index += 1
    return steps

def change_linux_step_command(steps, lines, config_yaml):
    index = 0
    for step in steps:
        name = step.get('name')
        if name == AAT_API.linux_command_step_name:
            ip = ip_completion(lines[index])
            url = url_completion(lines[index])
            # ��ȡ����
            domain = get_domain_name(url)
            # python3 add_rule_to_etc_hosts.py ip url etc_hosts_path
            # commands = step['parameters']['Commands']['value'].split()
            python = "python3"
            command = "{} {} {} {} {};cat {}|grep {} ".format(python, config_yaml['script_path'], ip, domain, config_yaml['hosts_path'], config_yaml['hosts_path'], domain)
            step['parameters']['Commands']['value'] = command
            index += 1
    return steps

def get_test_step_by_name(steps, step_name):
    for step in steps:
        name = step.get('name')
        if name == step_name:
            return step

def get_step_template(steps, start_step_name, end_step_name=None):
    # ��ȡ steps �� start_step_name �� end_step_name ֮ǰΪֹ�� steps �������� end_step_name��
    # ���û�� end_step_name�����ȡ������ step
    if end_step_name is None:
        end_step_name = start_step_name

    start = None
    end = len(steps)
    for index, step in enumerate(steps):
        name = step.get('name')
        if name == start_step_name:
            start = index
        elif name == end_step_name and start is not None:
            end = index
            break
    if start is None:
        print("not have step name:{}".format(start_step_name))
        return
    # print("get_step_template", steps)
    return steps[start:end]

def delete_step(steps, step_name, delete_len):
    # ɾ�� steps �� step name �� step_name ��ʼ�ļ��� step
    delete_index = None
    for index, step in enumerate(steps):
        name = step.get('name')
        if name == step_name:
            delete_index = index
    if delete_index is None:
        return
    result = steps[:delete_index]
    result.extend(steps[delete_index + delete_len:])
    return result

def get_step_num(steps, step_name):
    return len([step for step in steps if step.get('name') == step_name])

def verify_epg_pss(log):
    pass

def verify_case_pass(log, lines):
    # fail: ��֤ʧ��, pass: ��֤ͨ��
    result = []

    # l3_l7: AAT receive GET <---------- HTTP(S)_Service Response
    # l3: AAT receive TCP_only <---------- HTTP(S)_Service Response
    # l7: AAT <---------- HTTP_Response
    http_request = "---> HTTP"
    http_respone = "---- HTTP"
    # case �ڴ�������֮ǰ����
    if log.count("AAT ----------> Attach_Complete") == 0:
        print("case failed befor http step, please check log:\n{}".format(log))
        sys.exit()

    def epg_result_check(epg_log, code):
        if epg_log != "":
            return True
        # if "apn-in-use: cmnet" in epg_log and code in epg_log:
        #     return True
        return False

    datas = log.split("---- HTTP")[1:]
    for index, data in enumerate(datas):
        code = lines[index].get('code')
        if epg_result_check(data, code):
            result.append('pass')
        else:
            result.append('failed')
    # ���ִ�е����� failed ���� case ûִ������������
    if len(result) != len(lines):
        result.append('failed')
    return result

def change_case_template_step_num(step_datas, change_step_num, start_step_name, end_step_name=None):
    template_step = get_step_template(step_datas, start_step_name, end_step_name)
    case_template_step_num = get_step_num(step_datas, start_step_name)
    diff_len = change_step_num - case_template_step_num
    while diff_len != 0:
        if diff_len > 0:
            # case https step ���ˣ���Ҫ���
            step_datas.extend(template_step)
            diff_len -= 1
        elif diff_len < 0:
            # case https step ���ˣ���Ҫɾ��
            step_datas = delete_step(step_datas, start_step_name, len(template_step))
            diff_len += 1
    return step_datas

def change_case_and_execute_and_analyze_log(aat, server_id, case_id, case_data, lines):
    # �޸� case ����
    aat.change_test_case_by_id(server_id, case_id, case_data)
    # ִ�� case
    task_id = aat.start_test_case_execution(server_id, case_id)
    # ��ȡִ�н��
    log_id = aat.get_test_execution_log_id(server_id, task_id, case_id)
    log = aat.get_test_case_log(server_id, log_id)
    print('logID:{}\n'.format(log_id), log)
    # ����ִ�н������������µ� excel ����
    case_verifys = verify_case_pass(log, lines)
    return case_verifys

def update_verify_to_line(lines, verify_result, line_index):
    for index, verify in enumerate(verify_result):
        lines[index + line_index]['verify'] = verify
    return lines


def modify_case(aat, lines, type_str, config_yaml):
    template_end_step_name = None

    if 'l3' in type_str and 'l7' in type_str:
        # l3+(l4)?+l7+http(s)?
        print('l3_l7 {}:\n'.format(len(lines)), lines)
        case_name = config_yaml['l3_l7']
        template_start_step_name = AAT_API.linux_command_step_name
        # return
    elif 'l3' in type_str:
        # l3
        print('l3 {}:\n'.format(len(lines)), lines)
        case_name = config_yaml['l3']
        template_start_step_name = AAT_API.https_step_name
        # return
    elif 'l7' in type_str:
        # l7+http(s)?
        print('l7 {}:\n'.format(len(lines)), lines)
        case_name = config_yaml['l7']
        template_start_step_name = AAT_API.https_step_name
        template_end_step_name = AAT_API.ue_detach_step_name
        # return

    # ��ȡ case �� id
    server_id = aat.server_id
    case_id = aat.get_test_case_id(server_id, case_name)

    # �����������ݣ�ÿ����ദ�� n ������
    index = 0
    # for index in range(0, len(lines), max_modify_step):
    while index < len(lines):
        # ��ȡ case �� json ����
        case_data = aat.get_test_case_by_id(server_id, case_id)
        # print('case_data\n', case_data, '\n')
        step_data = case_data['testStepList']
        # �Ա� case https step ����������Ҫ���������������step ����������� step��������� step
        line_datas = lines[index:index+max_modify_step]
        step_data = change_case_template_step_num(step_data, len(line_datas), template_start_step_name, template_end_step_name)

        # �޸� case ������
        # �޸� epg �� apn
        step_data = change_case_epg_and_apn(aat, server_id, step_data, config_yaml)
        if 'l3' in type_str and 'l7' in type_str:
            step_data = change_linux_step_command(step_data, line_datas, config_yaml)
            step_data = change_https_step_https_resource(aat, server_id, step_data, line_datas)
        elif 'l3' in type_str:
            step_data = change_https_step_https_resource(aat, server_id, step_data, line_datas)
        elif 'l7' in type_str:
            step_data = change_https_step_https_resource(aat, server_id, step_data, line_datas)
        case_data['testStepList'] = step_data

        # ִ�� case ���������
        case_verifys = change_case_and_execute_and_analyze_log(aat, server_id, case_id, case_data, line_datas)
        # ��ִ�н�����µ� lines �ֵ���
        update_verify_to_line(lines, case_verifys, index)
        # ���һ�����ݶ�û��ִ�У�����ֹ�������У���� Log ��־����ʾִ���߼�� case
        if len(case_verifys) == 0:
            print("***")
            sys.exit()
        # �¸� case �����ݿ�ʼ�±꣬����������ִ���ˣ��±�����Ӷ���
        index += len(case_verifys)

    return lines

def save_data_to_excel(file_path, type_date):
    wb = openpyxl.Workbook()
    sheet = wb.create_sheet(title="������")
    index = 1

    def wirte_one_row(sheet, row_num, datas):
        for index, data in enumerate(datas):
            sheet.cell(row_num, index + 1).value = data

    for type_str, datas in type_date.items():
        if index == 1:
            # д��ͷ
            keys = list(datas[0].keys())
            if "verify" not in keys:
                keys.append("verify")
            wirte_one_row(sheet, index, keys)
            index += 1
        # д����
        for data in datas:
            if "verify" not in data:
                # ûִ�й������ݣ���д�� excel
                continue
            wirte_one_row(sheet, index, data.values())
            index += 1
    wb.save(file_path)

def sudo_command(sudo_password, command):
    return os.system("echo {} | sudo -S {}".format(sudo_password, command))

def ssh_local_no_password():
    rsa_exist = os.system("ls ~/.ssh/ | grep id_rsa.pub")
    if "id_rsa" not in rsa_exist:
        keygen = os.system("ssh-keygen -t rsa -N '' -f ~/.ssh/id_rsa")
    authorized_keys = os.system("cat ~/.ssh/authorized_keys")
    id_rsa = os.system("cat ~/.ssh/id_rsa.pub")
    if id_rsa not in authorized_keys:
        os.system("cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys")
    sudo_command("", "service ssh restart")

if __name__== "__main__" :
    # config_yaml = {
    #     'excel_path': './date_dpi.xlsx',
    #     'output_path': './date_dpi_output.xlsx',
    #     'aat_domain': 'https://10.178.36.122:13931',
    #     'user_name': 'sysadm',
    #     'password': 'Aat7777777',
    #     'l7': 'aat_dpi_l7',
    #     'l3_l7': 'aat_dpi_l3_l7',
    #     'l3': 'aat_dpi_l3',
    #     'epg_name': 'GZSAEGW2001BEr',
    #     'hosts_path': "/etc/hosts",
    #     'script_path': "./add_rule_to_etc_hosts.py",
    #     'date_select_max_num': 15,
    #     'epg_with_apn': {'GZSAEGW2001BEr': 'gzcmnet2001.gd'},
    # }
    # config_yaml = {
    #     'excel_path': '/home/ericsson/date_dpi.xlsx',
    #     'output_path': '/home/ericsson/date_dpi_output.xlsx',
    #     'aat_domain': 'https://188.4.62.189:33341',
    #     'user_name': 'sysadm',
    #     'password': 'ChangeMe11',
    #     'l7': 'aat_dpi_l7',
    #     'l3_l7': 'aat_dpi_l3_l7',
    #     'l3': 'aat_dpi_l3',
    #     'epg_name': 'GZSAEGW2001BEr',
    #     'hosts_path': "/etc/hosts",
    #     'script_path': "/home/ericsson/add_rule_to_etc_hosts.py",
    #     'date_select_max_num': 15,
    #     'epg_with_apn': {'GZSAEGW2001BEr': 'gzcmnet2001.gd'},
    #
    # }

    try:
        # # ��ӵ�ǰ�û��� /etc/hosts ��дȨ��
        # chmod_command = "chmod +3 {}".format(hosts_path)
        # sudo_command(config_yaml['aat_cli_password'], chmod_command))

        # ��ȡ�����ļ�
        with open('./config.yaml', 'r') as config:
            config_yaml = load(config, Loader=FullLoader)
        hosts_path = config_yaml['hosts_path']
        print('config_yaml', config_yaml)

        # # ���� /etc/hosts
        # cp_command = "cp {0} ~/hosts.cp".format(hosts_path)
        # os.system(cp_command)


        # # ��ȡ excel
        type_date = read_dpi_config(config_yaml['excel_path'], config_yaml['date_select_max_num'])
        # type_date = {'l3+l7+http': [{'line_num': 918, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '111.40.195.239', 'protocol': '', 'l4': '', 'l7': 'http://*mgsplive.miguvideo.com/*'}, {'line_num': 919, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '111.40.195.234', 'protocol': '', 'l4': '', 'l7': 'http://*mgsplive.miguvideo.com/*'}, {'line_num': 923, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '111.40.195.239', 'protocol': '', 'l4': '', 'l7': 'http://*mgsplive.miguvideo.com:*'}, {'line_num': 924, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '111.40.195.234', 'protocol': '', 'l4': '', 'l7': 'http://*mgsplive.miguvideo.com:*'}, {'line_num': 1186, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '2409:8c60:1200:2:8000:0:b00:86/128', 'protocol': '', 'l4': '', 'l7': 'http://*mgspvod.miguvideo.com/*'}, {'line_num': 1187, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '2409:8c62:e10:5a:8000:0:b00:215/128', 'protocol': '', 'l4': '', 'l7': 'http://*mgspvod.miguvideo.com/*'}, {'line_num': 1188, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '2409:8c6a:b021:40:8000:0:b00:96/128', 'protocol': '', 'l4': '', 'l7': 'http://*mgspvod.miguvideo.com/*'}, {'line_num': 1189, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '2409:8c70:3a10:0:8000:0:b00:215/128', 'protocol': '', 'l4': '', 'l7': 'http://*mgspvod.miguvideo.com/*'}, {'line_num': 1190, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '2409:8c70:3a08:7:8000:0:b00:215/128', 'protocol': '', 'l4': '', 'l7': 'http://*mgspvod.miguvideo.com/*'}, {'line_num': 1191, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '2409:8c50:a00:2073:8000:0:b00:86/128', 'protocol': '', 'l4': '', 'l7': 'http://*mgspvod.miguvideo.com/*'}, {'line_num': 1192, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '2409:8c44:b00:ff06:8000:0:b00:215/128', 'protocol': '', 'l4': '', 'l7': 'http://*mgspvod.miguvideo.com/*'}, {'line_num': 1193, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '2409:8c54:9010:10:8000:0:b00:215/128', 'protocol': '', 'l4': '', 'l7': 'http://*mgspvod.miguvideo.com/*'}, {'line_num': 1194, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '2409:8c28:30b0:6:8000:0:b00:215/128', 'protocol': '', 'l4': '', 'l7': 'http://*mgspvod.miguvideo.com/*'}, {'line_num': 1195, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '2409:8c20:5021:10c:8000:0:b00:86/128', 'protocol': '', 'l4': '', 'l7': 'http://*mgspvod.miguvideo.com/*'}, {'line_num': 1196, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000006, 'name': 'mgsp_00', 'l3': '2409:8c20:6ed1:10d:8000:0:b00:215/128', 'protocol': '', 'l4': '', 'l7': 'http://*mgspvod.miguvideo.com/*'}, {'line_num': 3182, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '111.13.40.91', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}, {'line_num': 3183, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '111.20.14.155', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}, {'line_num': 3184, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '111.20.14.163', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}, {'line_num': 3185, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '111.31.82.78', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}, {'line_num': 3186, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '111.32.146.242', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}, {'line_num': 3187, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '111.48.160.51', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}, {'line_num': 3188, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '111.48.160.55', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}, {'line_num': 3189, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '112.48.187.89', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}, {'line_num': 3190, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '112.50.96.82', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}, {'line_num': 3191, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '117.139.22.177', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}, {'line_num': 3192, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '117.147.209.179', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}, {'line_num': 3193, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '117.148.174.44', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}, {'line_num': 3194, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '117.157.247.43', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}, {'line_num': 3195, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '117.157.247.51', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}, {'line_num': 3196, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '117.167.113.163', 'protocol': '', 'l4': None, 'l7': 'http://*.xmcdn.com/*'}], 'l3': [{'line_num': 3179, 'flag': '����', 'description': '�����������', 'code': 1740000002, 'name': 'mgspqwdx_00', 'l3': '39.173.75.14', 'protocol': None, 'l4': None, 'l7': None},], 'l7+https': [{'line_num': 3181, 'flag': '����', 'description': '�����߲����', 'code': 1740000002, 'name': 'mgspqwdx_00', 'l3': None, 'protocol': None, 'l4': None, 'l7': 'https://*.aikan.miguvideo.com'}], 'l3+l4+l7+https': [{'line_num': 3258, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '111.13.40.91', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}, {'line_num': 3259, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '111.20.14.155', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}, {'line_num': 3260, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '111.20.14.163', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}, {'line_num': 3261, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '111.31.82.78', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}, {'line_num': 3262, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '111.32.146.242', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}, {'line_num': 3263, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '111.48.160.51', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}, {'line_num': 3264, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '111.48.160.55', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}, {'line_num': 3265, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '112.48.187.89', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}, {'line_num': 3266, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '112.50.96.82', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}, {'line_num': 3267, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '117.139.22.177', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}, {'line_num': 3268, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '117.147.209.179', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}, {'line_num': 3269, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '117.148.174.44', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}, {'line_num': 3270, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '117.157.247.43', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}, {'line_num': 3271, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '117.157.247.51', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}, {'line_num': 3272, 'flag': '����', 'description': '������Ϲ���', 'code': 1750000089, 'name': 'xmly_00', 'l3': '117.167.113.163', 'protocol': '', 'l4': 443, 'l7': 'https://*.xmcdn.com'}]}
        # type_date['l3'] = type_date['l3']*15
        # print(type_date)

        for key in type_date:
            print(key, len(type_date[key]))

        # print(type_date['l3+l4+l7+https'])
        # print(type_date['l3'][0].get('l7') is None)

        # ��ʼ�� aat api
        aat = AAT_API(config_yaml['aat_domain'], config_yaml['user_name'], config_yaml['password'])


        # ���� excel �����޸� case��ִ�в���ȡ case ִ�н��
        for type_str, lines in type_date.items():
            modify_case(aat, lines, type_str, config_yaml)

    finally:
        # # ɾ�����ܴ����� https resource
        # remove_https_resource(aat, aat.server_id)

        # ��ִ�н������� excel
        save_data_to_excel(config_yaml['output_path'], type_date)

        # # �����޸ĺ�� /etc/hosts, ��ԭ /etc/hosts
        # cp_command = "cp {0} ~/hosts.cp2;cat ~/hosts.cp > {};rm ~/hosts.cp".format(hosts_path)
        # os.system(cp_command)

        #
        input("Enter any key to finish the program")


