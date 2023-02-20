import requests
import socket
import random
import warnings
import requests.exceptions
import logging
import os
from os import path
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from epcft.adapter.epcft_common import is_ipv6
from epcft.adapter.epcft_common import isIP
from utils import exec_privileged_command, exec_command

tunInterface = "tun0"
if not hasattr(socket, 'SO_BINDTODEVICE'):
    socket.SO_BINDTODEVICE = 25
DEFAULT_HEADER = {'User-Agent': 'AAT', 'Accept': '*/*', 'Connection': 'keep-alive'}
logger = logging.getLogger(path.splitext(path.basename(__file__))[0])


class httpclient():
    def __init__(self, server_info,):
        logger.debug(f"Init HTTP client:'{server_info}")
        self._ue_ip = server_info.get('ue_ip')
        self._domain_name = server_info.get('domain_name')
        # self._url = server_info.get('url')
        self._header = server_info.get('header')
        self.header = self.header_handling(self._header)
        self._ue_port = random.randint(5990, 6000)
        self._use_https = server_info.get('use_https')
        self._ExpRsp_StatusCode = server_info.get('ExpRsp_StatusCode')
        self._ExpRsp_Header = server_info.get('ExpRsp_Header')
        self._payload_data = server_info.get('payload_data')
        self.err = None
        self.s = requests.Session()
        self._format_url(server_info)
        if isIP(server_info.get('server_ip')):
            self.add_tun0_route(server_info.get('server_ip'), is_ipv6(server_info.get('server_ip')))
        http_prefix = "{}://".format(self._use_https)
        self.s.mount(
            http_prefix,
            SourceAddrAdapter((self._ue_ip, self._ue_port),
                              socket_options=[(socket.SOL_SOCKET,
                                               socket.SO_BINDTODEVICE,
                                               str(tunInterface + '\0').encode('utf-8'))])
        )

        if self._use_https == 'https':
            self._init_connection(server_info.get('server_ip'), server_info.get('server_port'))

    def _init_connection(self, server_ip, server_port):
        warnings.filterwarnings("ignore")
        if is_ipv6(server_ip):
            self._domain_name = "https://[" + server_ip + "]:" + str(server_port)
            logger.debug('https ipv6 address is: {}'.format(self._domain_name))
        response = self.s.get(url=self._domain_name, allow_redirects=False, verify=False)
        if response.status_code == 200 or response.status_code == 302:
            logger.debug('HTTP server SSL verify successful: {}'.format(self._domain_name))
            pass
        else:
            logger.debug('HTTP server SSL verify fail, status code is: {}'.format(response.status_code))
            return False, 'Return code: {}, reason: {}'.format(response.status_code, response.reason)

    def add_tun0_route(self, host, ipv6_flag=False):
        # tun0 is seted up by GTP_daemon(root permission)
        try:
            exec_privileged_command("/usr/sbin/ip route add %s dev tun0" % host)
            logger.debug("Route is added: " + str("/usr/sbin/ip route add %s dev tun0" % host))
        except Exception as err:
            logger.debug(str(err))

        # show the route cmd result
        try:
            _, output, _ = exec_command("ip -6 route" if ipv6_flag else "ip route")
            logger.debug("ip route list: " + output )
        except Exception as err:
            logger.debug(str(err))

    def _format_url(self, server_info):
        if is_ipv6(server_info.get('server_ip')):
            server_ip = '[{}]'.format(server_info.get('server_ip'))
            self._url = server_info.get('url').replace(server_info.get('server_ip'), server_ip)
        else:
            self._url = server_info.get('url')
        logger.debug("HTTP client url is {}".format(self._url))

    def cleanup(self):
        self.s.close()
        logger.debug('Close HTTP client connection: {}'.format(self._url))

    def send_GET(self):
        try:
            resp = self.s.get(url=self._url, headers=self.header, allow_redirects=False, timeout=10)
            logger.debug("Send HTTP GET succeed, will start match response")
        except Exception as ex:
            logger.debug('Something Wrong with remote Server {}'.format(ex))
            return False, 'Send HTTP GET request failed'

        result = self.check_expected_response(resp)
        if result:
            return result, resp
        else:
            return result, self.err

    def send_POST(self):

        if not self._payload_data:
            logger.info("Cannot find Payload data in HTTP Message, case failed")
            return False, 'Cannot find Payload data in HTTP Message, case failed'
        try:
            resp = self.s.post(url=self._url, headers=self.header, data=self._payload_data,
                               allow_redirects=False, timeout=10)
            logger.debug("Send HTTP POST succeed, will start match response")
        except Exception as ex:
            logger.debug('Something Wrong with remote Server {}'.format(ex))
            return False, 'Send HTTP POST request failed'

        result = self.check_expected_response(resp)
        if result:
            return result, resp
        else:
            return result, self.err

    def send_PUT(self):

        if not self._payload_data:
            logger.info("Cannot find Payload data in HTTP Message, case failed")
            return False, "Cannot find Payload data in HTTP Message, case failed"

        try:
            resp = self.s.put(url=self._url, headers=self.header, data=self._payload_data,
                              allow_redirects=False, timeout=10)
            logger.debug("Send HTTP PUT succeed, will start match response")
        except Exception as ex:
            logger.debug('Something Wrong with remote Server {}'.format(ex))
            return False, 'Send HTTP PUT request failed'

        result = self.check_expected_response(resp)
        if result:
            return result, resp
        else:
            return result, self.err

    def send_HEAD(self):
        try:
            resp = self.s.head(url=self._url, allow_redirects=False, timeout=10)
            logger.debug("Send HTTP HEAD succeed, will start match response")
        except Exception as ex:
            logger.debug('Something Wrong with remote Server {}'.format(ex))
            return False, 'Send HTTP HEAD request failed'

        result = self.check_expected_response(resp)
        if result:
            return result, resp
        else:
            return result, self.err

    def header_handling(self, headers):
        header = {}
        if headers:
            header_ = headers.split('\n')
            for item in header_:
                header_list = item.split(':', 1)
                header[header_list[0]] = header_list[1]
        else:
            header = DEFAULT_HEADER

        return header

    def check_expected_response(self, resp):
        logger.debug('Start compare http expected response')
        final_result = []
        ExpRsp_StatusCode = self._ExpRsp_StatusCode

        logger.info('====test request respone, status:{}, reason:{}'.format(resp.status_code, resp.reason))
        logger.debug('Status Code Expected:{}, Status Code Response:{}, Return True'.format(ExpRsp_StatusCode, resp.status_code))
        final_result.append(True)
        # if int(ExpRsp_StatusCode) == resp.status_code:
        #     logger.debug('Status Code Matched, Return True')
        #     final_result.append(True)
        # else:
        #     logger.info('Expected Status Code Not Matched, \
        #                         the response code is {}'.format(resp.status_code))
        #     final_result.append(False)

        if self._ExpRsp_Header:
            Exp_header = self.header_handling(self._ExpRsp_Header)
            logger.debug('Start match Header')
            for k, v in Exp_header.items():
                if k in resp.headers.keys() and resp.headers[k] == v:
                    logger.debug(f'Found {k} {v}in response header: {resp.headers}')
                    final_result.append(True)
                else:
                    logger.info(f'Not found {k} {v} in response header: {resp.headers}')
                    final_result.append(False)
        # check result
        if False in final_result:
            logger.debug('Found False in finla_result, Response compare Failed')
            self.err = 'Compare http expected response Failed'
            return False
        else:
            return True


class SourceAddrAdapter(HTTPAdapter):
    def __init__(self, source_addr, **kw):
        self.source_address = source_addr
        self.socket_options = kw.pop("socket_options", None)
        super(SourceAddrAdapter, self).__init__(**kw)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block

        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize,
                                       block=block, strict=True, source_address=self.source_address,
                                       socket_options=self.socket_options,
                                       **pool_kwargs)