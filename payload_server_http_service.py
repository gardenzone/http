import logging
import json
from .http import http
import random
from os import path
from ..constant import HTTP_RANDOM_PORT_MIN, HTTP_RANDOM_PORT_MAX

from ..payload_util import payload_server_itf
from ..payload_util import SetSourceAddr
from .h2client import H2Client
from .httpclient import httpclient
from ..dns.dns import DNS_Resolver
from ..dns.dns import get_pco_dns_addr, get_network_dns_addr, get_ue_ip
from epcft.adapter.epcft_common import isIP, is_valid_domain
from ..payload_util import AddRoute
from socket import getaddrinfo

logger = logging.getLogger(path.splitext(path.basename(__file__))[0])


class payload_server_http_service(payload_server_itf):
    def __init__(self, conn_aat, payload):
        '''
        HTTP_REQUEST structure :
        {'protocol': 'HTTP',
        'message_type': 'http_service', 
        'message_id': 39,
        'sour_IPAddr_v4': '640001E4',
        'is_gsm_payload': False,
        'message_data': {
            'http_service':{
                'http_node_type': 'HTTPs_Service_SIM',
                'http_version': 'HTTP 1.1',
                'http_type': 'HTTP',
                'http_ip': '10.38.207.141',
                'http_port': 1025, 
                'eth_interface': 'eth2',
                'request_methods': 'GET',
                'session_bearer_id': '5', 
                'expected_response': {'status_code': '200'}}}}
        '''
        self.response = {
            'protocol': 'HTTP',
            'message_type': 'http_response',
            'message_id': '',
            'dest_IPAddr': '',
            'message_data': {
                'http_response': {
                    'status': '',
                    'reason': '',
                    'content_length': '',
                    'content_type': '',
                    'path': ''
                }
            }
        }

        self.err = {
            'protocol': 'HTTP',
            'message_type': 'http_error',
            'message_id':'',
            'dest_IPAddr': '',
            'message_data':{'http_error': {'err_msg': ''}}
        }

        self.request = payload
        self.res = None
        self.conn_aat = conn_aat
        self.server_info = {}
        self.ue_addr_ip = ''
        self.error_msg = None
        self.http_client = None
        self.http2_err_msg = None

    def get_ue_addr(self):
        addr_v4 = None
        addr_v6 = None
        if('sour_IPAddr_v4' in list(self.request.keys())):
            addr_v4 = self.request['sour_IPAddr_v4']
        if('sour_IPAddr_v6' in list(self.request.keys())):
            addr_v6 = self.request['sour_IPAddr_v6']
        logger.debug("The UE source IP addresses are: {} and {}.".format(addr_v4, addr_v6))
        return addr_v4, addr_v6

    def send_request(self):
        logger.debug("Received http request is: {}".format(self.request))

        flag_server = self.convert_httpmessage_serverinfo()
        if not flag_server:
            self.error_msg = 'host name of SUT HTTP(s) Server incorrect.'
            logger.debug("host name of SUT HTTP(s) Server is not correct. {}".format(self.error_msg))
            self.send_err_to_aat(self.error_msg)
            self.error_msg = None
            return flag_server

        http_method = self.request['message_data']['http_service'].get('request_methods')
        if http_method == "TCP_only":
            server_ip = self.server_info.get('server_ip')
            server_port = self.server_info.get('server_port')
            logger.info(f'AAT TCP message send TCP handshake ----------> server {server_ip}:{server_port}')
            try:
                self.http_client = httpclient(self.server_info)
                self.res = {
                    'status': 200, 
                    'reason': 'Forbidden', 
                    'headers': {
                        'Server': 'openresty', 'Date': 'Fri, 17 Feb 2023 08:09:56 GMT', 
                        'Content-Type': 'text/html', 
                        'Content-Length': '150', 
                        'Connection': 'keep-alive', 
                        'via': 'CHN-SNxianyang-AREACMCC1-CACHE44[1]'
                        }, 
                    'content_type': 'text/html', 
                    'content_length': '150'
                    }
                logger.info(f'AAT TCP message receive TCP handshake <---------- server {server_ip}:{server_port}')
            except Exception as ex:
                logger.info(f'AAT TCP message send TCP handshake fail. Fail reason {str(ex)}')
            return True

        try:
            self.http_client = httpclient(self.server_info)
            logger.info(f'AAT http message send {http_method}----------> http(s)_service_request')
        except Exception as ex:
            logger.error(str(ex))
            self.error_msg = 'HTTP Client connection failed'

        if (self.error_msg):
            logger.debug("http connection failed with error: {}".format(self.error_msg))
            self.send_err_to_aat(self.error_msg)
            self.error_msg = None
            return False

        if http_method == 'GET':
            result, res = self.http_client.send_GET()
        elif http_method == 'PUT':
            result, res = self.http_client.send_PUT()
        elif http_method == 'HEAD':
            result, res = self.http_client.send_HEAD()
        elif http_method == 'POST':
            result, res = self.http_client.send_POST()
        else:
            logger.debug('Found wrong http method in message, Return False')
            res = 'Found wrong http method in message, Return False'
            result = False

        if result:
            self.res = self.response_processing(res)
            logger.debug("https service response is: {}".format(self.res))
            logger.info(f'AAT http message send {http_method}<---------- http(s)_service_response')
            return True
        else:
            self.error_msg = res
            logger.debug("http receive failed with error: {}".format(self.error_msg))
            self.send_err_to_aat(self.error_msg)
            self.error_msg = None
            return False

    def response_processing(self, resp):
        final_resp = {
            'status' : resp.status_code,
            'reason' : resp.reason,
            'headers' : resp.headers,
            'content_type' : resp.headers.get('Content-Type'),
            'content_length' : resp.headers.get('Content-Length') if resp.headers.get('Content-Length') else 'no_length'
        }
        return final_resp

    def __SetDestAddr(self):
        if('sour_IPAddr_v4' in self.request):
            dest_addr = self.request['sour_IPAddr_v4']
        elif('sour_IPAddr_v6' in self.request):
            dest_addr = self.request['sour_IPAddr_v6']
        return dest_addr

    def encode_payload(self):
        try:
            logger.debug("encode_payload self res : {}".format(self.res))
            self.response['message_data']['http_response']['status'] = int(self.res.get('status'))

            if self.res.get('reason'):
                self.response['message_data']['http_response']['reason'] = self.res.get('reason')
            else:
                self.response['message_data']['http_response']['reason'] = 'OK'

            if self.server_info['url'] != '':
                self.response['message_data']['http_response']['path'] = self.server_info['url']
                self.response['message_data']['http_response']['content_length'] = self.res.get('content_length')
                # content_type = self.res.headers['Content-Type'].split(';')[0]
                self.response['message_data']['http_response']['content_type'] = self.res.get('content_type')

            self.response['message_id'] = self.request['message_id']
            self.response['dest_IPAddr'] = self.__SetDestAddr()
            logger.debug("The raw http response is {}".format(self.response))

            data_json = json.dumps(self.response)
            logger.debug("The raw http response is encoded as: {}".format(data_json))
            return data_json
        except Exception as err:
            logger.error("encode_payload with error: {}".format(err))
            self.error_msg = "encode_payload with error"
            self.send_err_to_aat(self.error_msg)
            self.error_msg = None

    def encode_errmsg(self, msg):
        self.err['message_id'] = self.request['message_id']
        self.err['dest_IPAddr'] = self.__SetDestAddr()
        self.err['message_data']['http_error']['err_msg'] = "[HTTP(S) Service failed] " + msg
        logger.debug("The raw http error message is: {}".format(self.err))

        err_json = json.dumps(self.err)
        logger.debug("The raw http error message is encoded as: {}".format(err_json))

        return err_json

    def send_err_to_aat(self, ErrMsg):
        err = self.encode_errmsg(ErrMsg)
        self.conn_aat.send(err.encode('utf-8'))
        logger.debug("http error message is sent to AATTE successfully! ")

    def send_response_to_aat(self):
        data = self.encode_payload()
        self.conn_aat.send(data.encode('utf-8'))
        logger.debug("http response is sent to AATTE successfully! ")

    def send_req_and_process_response(self):
        # If sending request is successful, receive response, otherwise do nothing.
        flagHttp = self.request['message_data']['http_service'].get('http_version')
        if flagHttp and flagHttp == 'HTTP 2':
            if self.handle_http2_message():
                self.send_response_to_aat()
            else:
                self.send_err_to_aat(self.http2_err_msg )
        else:
            if self.send_request():
                self.send_response_to_aat()

            if self.http_client:
                self.http_client.cleanup()

        return

    def query_domain_ip(self, ue_addr_ip, server_addr_ip, httpserver_sim_ip, httpserver_sim_port):
        dns_server_query_ip = ''
        if server_addr_ip and ue_addr_ip:
            for item in server_addr_ip:
                server_ip = []
                server_ip.append(item)
                AddRoute(item, httpserver_sim_port)
                for ue_ip_value in ue_addr_ip:
                    dns_server = DNS_Resolver(ue_ip_value, httpserver_sim_ip, server_ip)
                    dns_server_query_ip = dns_server._query()
                    if dns_server_query_ip == "":
                        logger.warning("DNS doamin query ip failed, server ip is {} hostname {} flag. PDN ip {} address.".format(server_ip, httpserver_sim_ip, ue_ip_value))
                    if dns_server_query_ip:
                        httpserver_sim_ip = dns_server_query_ip
                        return httpserver_sim_ip, True
        return httpserver_sim_ip, False

    def convert_httpmessage_serverinfo(self):
        try:
            logger.debug('convert httpmessage serverinfo start:')
            httpserver_dic = self.request['message_data']['http_service']
            # get NodeType
            httpserver_type = httpserver_dic.get('http_type')
            httpserver_sim_protocol = 'http' if httpserver_type == 'HTTP' else 'https'
            # get Port
            port = httpserver_dic.get('http_port')
            httpserver_sim_port = port if port else 80
            # get ip
            httpserver_sim_ip = httpserver_dic.get('http_ip')
            ue_addr_v4, ue_addr_v6 = self.get_ue_addr()
            if httpserver_sim_ip:
                pass
            else:
                httpserver_sim_ip = httpserver_dic.get('hostname')
                if not isIP(httpserver_sim_ip) and is_valid_domain(httpserver_sim_ip):
                    logger.debug("HTTP message hostname is : {}".format(httpserver_sim_ip))
                    ue_addr_ip = get_ue_ip(ue_addr_v4, ue_addr_v6)
                    pco_server_addr_ip = get_pco_dns_addr(self.request, 'http_service')
                    net_server_addr_ip = get_network_dns_addr(self.request, 'http_service')
                    httpserver_sim_ip, pco_query_falg = self.query_domain_ip(ue_addr_ip, pco_server_addr_ip, httpserver_sim_ip, httpserver_sim_port)
                    if not pco_query_falg:
                        logger.debug("HTTP : DNS pco server query failed, bengin network server ip query.")
                        httpserver_sim_ip, net_query_falg = self.query_domain_ip(ue_addr_ip, net_server_addr_ip, httpserver_sim_ip, httpserver_sim_port)
                    if not net_query_falg:
                        infolist = getaddrinfo(httpserver_sim_ip, httpserver_sim_port)
                        httpserver_sim_ip = infolist[0][4][0]

            domain_name = httpserver_sim_protocol + '://' + httpserver_sim_ip + ':' + str(httpserver_sim_port)
            url = httpserver_dic.get('url')
            if url:
                final_url = domain_name + url
            else:
                final_url = domain_name

            header = httpserver_dic.get('header')
            ExpRsp_StatusCode = httpserver_dic['expected_response']['status_code']
            ExpRsp_Header = httpserver_dic['expected_response'].get('response_header')
            payload_data = httpserver_dic.get('payload_body')
            sour_addr = SetSourceAddr(httpserver_sim_ip, httpserver_sim_port, ue_addr_v4, ue_addr_v6)
            self.ue_addr_ip = sour_addr

            self.server_info = {
                'ue_ip' : self.ue_addr_ip,
                'server_ip': httpserver_sim_ip,
                'server_port': httpserver_sim_port,
                'domain_name': domain_name,
                'url': final_url,
                'header': header,
                'use_https': httpserver_sim_protocol,
                'ExpRsp_StatusCode': ExpRsp_StatusCode,
                'ExpRsp_Header': ExpRsp_Header,
                'payload_data': payload_data
            }

            logger.debug(f'convert httpmessage serverinfo finish, result is: {self.server_info}')
            return True
        except Exception as err:
            logger.debug("convert httpmessage serverinfo error: {}".format(err))
            return False

    def handle_http2_message(self):
        flag_server = self.convert_httpmessage_serverinfo()
        if not flag_server:
            self.http2_err_msg = 'host name of SUT HTTP(s) Server incorrect.'
            logger.debug(self.http2_err_msg )
            return flag_server

        # http_method = test_step['parameters'].get('Request_Methods')
        http_method = self.request['message_data']['http_service'].get('request_methods')
        h2_client = H2Client(self.server_info)
        logger.info('AAT http message send {} request'
                            .format(self.request['message_data']['http_service'].get('request_methods')))

        self.http2_err_msg = h2_client._err_ex
        if self.http2_err_msg:
            h2_client.cleanup()
            return False
        if http_method == 'GET':
            result, result_msg = h2_client.send_GET()
        elif http_method == 'PUT':
            result, result_msg = h2_client.send_PUT()
        elif http_method == 'HEAD':
            result, result_msg = h2_client.send_HEAD()
        elif http_method == 'POST':
            result, result_msg = h2_client.send_POST()
        else:
            self.http2_err_msg  = "Found wrong http method in message, Return False"
            logger.debug(self.http2_err_msg )
            return False

        logger.debug("handle_http2_mess ageresult msg is : {}.".format(result_msg))
        if result:
            self.res = self.process_result(result_msg)
        else:
            self.http2_err_msg = result_msg

        h2_client.cleanup()
        logger.info('AAT http message send {} _response'
                            .format(self.request['message_data']['http_service'].get('request_methods')))

        return result

    def process_result(self, result_msg):
        result_info = {
            'status' : str(result_msg.get(b':status')).split("'")[1],
            'content_type' : str(result_msg.get(b'content-type')).split("'")[1],
            'content_length' : str(result_msg.get(b'content-length')).split("'")[1],
            'server' : str(result_msg.get(b'server')).split("'")[1]
        }
        logger.debug("process_result msg is : {}.".format(result_info))
        return result_info
