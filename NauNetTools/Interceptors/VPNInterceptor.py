from binascii import hexlify
from urllib import parse

from Crypto.Cipher import AES
from requests import Response

from NauNetTools.Clients.NetworkClient import NetInterceptor, NetworkClient, PostRequestParam, RequestParam
from NauNetTools.Clients.SSOClient import SSOClient


class VPNUrlBuilder:
    __vpnUrlEncryptKey = 'wrdvpnisthebest!'
    __vpnUrlEncryptIV = 'wrdvpnisthebest!'
    __vpnUrlEncryptIVHex: str
    __vpnUrlEncryptIVByte: bytes
    __vpnUrlEncryptKeyByte: bytes

    def __init__(self):
        self.__vpnUrlEncryptKeyByte = self.__vpnUrlEncryptKey.encode('utf-8')
        self.__vpnUrlEncryptIVByte = self.__vpnUrlEncryptIV.encode('utf-8')
        self.__vpnUrlEncryptIVHex = hexlify(self.__vpnUrlEncryptIVByte).decode()

    @staticmethod
    def __text_right_append(text: str, mode: str) -> str:
        if mode == 'utf-8':
            segment_byte_size = 16
        else:
            segment_byte_size = 32
        if len(text) % segment_byte_size == 0:
            return text
        append_length = segment_byte_size - len(text) % segment_byte_size
        text += '0' * append_length
        return text

    def encrypt_vpn_url(self, host: str):
        text_len = len(host)
        host = self.__text_right_append(host, 'utf-8')
        host = host.encode('utf-8')
        cipher: AES = AES.new(self.__vpnUrlEncryptKeyByte, AES.MODE_CFB, iv=self.__vpnUrlEncryptIVByte,
                              segment_size=128)
        encrypted_host = cipher.encrypt(host)
        return self.__vpnUrlEncryptIVHex + hexlify(encrypted_host).decode()[0:text_len * 2]


# For http://vpn.nau.edu.cn
# Use as interceptor to translate real request into vpn request
# Only support GET and POST method
# Should be added as first interceptor
class VPNInterceptor(NetInterceptor):
    __user_id: str
    __user_pw: str
    __netTimeOut: int

    vpnHost = 'vpn.nau.edu.cn'
    vpnServer = 'http://' + vpnHost + ''
    __vpnSSOLoginService = vpnServer + '/login?cas_login=true&fromUrl=/'
    __vpnLogoutUrl = vpnServer + '/logout'
    __vpnUrlBuilder: VPNUrlBuilder

    def __init__(self, user_id: str, user_pw: str, time_out: int = 10):
        self.__requestUseVpn: dict = {}

        self.__user_id = user_id
        self.__user_pw = user_pw
        self.__netTimeOut = time_out
        self.__vpnUrlBuilder = VPNUrlBuilder()
        self.__noneVPNHost = []

    def set_none_vpn_host(self, host_list: list):
        if host_list is None:
            host_list = []
        else:
            self.__noneVPNHost = host_list

    def request_intercept(self, session: NetworkClient, request_code: int, param: RequestParam):
        if not self.__is_none_vpn_site(param):
            param.url = self.__build_vpn_url(param.url)
            self.__requestUseVpn[request_code] = True
        else:
            self.__requestUseVpn[request_code] = False

    def response_intercept(self, session: NetworkClient, request_code: int, param: RequestParam,
                           response: Response) -> Response:
        if response is not None and param is not None and request_code in self.__requestUseVpn.keys():
            if self.__requestUseVpn.pop(request_code):
                if type(param) == RequestParam:
                    last_request_method = 'GET'
                elif type(param) == PostRequestParam:
                    last_request_method = 'POST'
                else:
                    last_request_method = None
                if last_request_method is not None and not self._has_vpn_login(response):
                    sso_client = SSOClient(service_url=self.__vpnSSOLoginService, sso_host_check=False,
                                           sso_jump_host_check=False, request_login_client=session,
                                           with_interceptor=False)
                    vpn_response = sso_client.login(self.__user_id, self.__user_pw, response)
                    if vpn_response.is_success:
                        response = session.request(last_request_method, vpn_response.url, **param.kwargs)
        return response

    @staticmethod
    def _has_vpn_login(response: Response) -> bool:
        parse_result = parse.urlparse(response.url)
        if parse_result.netloc == SSOClient.ssoHost:
            return False
        if '南京审计大学统一身份认证登录' in response.text and 'vpn_hostname_data' in response.text:
            return False
        return True

    def __build_vpn_url(self, url: str) -> str:
        parse_result = parse.urlparse(url)
        vpn_url = self.vpnServer + '/' + parse_result.scheme
        if parse_result.port is not None and parse_result.port != 80 and parse_result.port != 443:
            vpn_url += '-' + str(parse_result.port)
        vpn_url += '/' + self.__vpnUrlBuilder.encrypt_vpn_url(parse_result.netloc)
        vpn_url += url[url.rindex(parse_result.path):len(url)]
        return vpn_url

    def __is_none_vpn_site(self, param: RequestParam) -> bool:
        url = param.url
        if url is None or url.isspace():
            return True
        parse_result = parse.urlparse(url)
        if parse_result.netloc.lower() == self.vpnHost:
            return True
        if parse_result.netloc.lower() in self.__noneVPNHost:
            return True
        if parse_result.netloc.lower() == SSOClient.ssoHost:
            if self.__vpnSSOLoginService.lower() in parse_result.params.lower():
                return True
            if 'logout' in parse_result.path.lower():
                return True
            if 'params' in param.kwargs.keys() and 'service' in param.kwargs['params'].keys():
                sso_service_url = param.kwargs['params']['service'].lower()
                sso_parse_result = parse.urlparse(sso_service_url)
                if sso_parse_result.netloc in self.__noneVPNHost:
                    return True
            if not parse_result.query.isspace():
                query_parse_result = parse.parse_qs(parse_result.query)
                if 'service' in query_parse_result.keys() and len(query_parse_result['service']) > 0:
                    sso_service_url = query_parse_result['service'][0].lower()
                    sso_parse_result = parse.urlparse(sso_service_url)
                    if sso_parse_result.netloc in self.__noneVPNHost:
                        return True
        return False

    def close(self, session: NetworkClient):
        session.get(self.__vpnLogoutUrl)


class VPNUtils:
    # Hosts all need to be lower characters
    noneVPNHost = [
        'my.nau.edu.cn',
        'jwc.nau.edu.cn',
        'jw.nau.edu.cn',
        'www.nau.edu.cn',
        'nau.edu.cn',
        'tw.nau.edu.cn',
        'xxb.nau.edu.cn',
        'xgc.nau.edu.cn'
    ]

    @staticmethod
    def is_use_school_vpn(client: NetworkClient) -> bool:
        return client.has_interceptor_type(VPNInterceptor)

    # Should be used before add other interceptors
    @staticmethod
    def use_school_vpn(client: NetworkClient, user_id: str, user_pw: str, use_none_vpn_list: bool = True):
        if not VPNUtils.is_use_school_vpn(client):
            interceptor = VPNInterceptor(user_id, user_pw)
            if use_none_vpn_list:
                interceptor.set_none_vpn_host(VPNUtils.noneVPNHost)
            client.add_interceptor(interceptor)
            return interceptor
        return None
