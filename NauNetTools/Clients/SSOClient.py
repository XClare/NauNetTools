from urllib import parse

from bs4 import BeautifulSoup
from requests import Response

from NauNetTools.Clients.NetworkClient import NetworkClient
from NauNetTools.Clients._UAPool import _UAPool


class ClientServiceResponse:
    is_success: bool = False

    # Only use SSO service will have following properties
    status_code: int = None
    text: str = None
    url: str = None
    is_service_login: bool = False
    headers: dict = {}


# For http://sso.nau.edu.cn
class SSOClient(NetworkClient):
    __netTimeOut: int
    ssoHost: str = 'sso.nau.edu.cn'
    __ssoLoginUrl: str = 'http://' + ssoHost + '/sso/login'
    __ssoLogoutUrl: str = 'http://' + ssoHost + '/sso/logout'
    __loginParam: list = ['lt', 'execution', '_eventId', 'useVCode', 'isUseVCode', 'sessionVcode', 'errorCount']
    __ssoJumpHostCheck: bool
    __ssoHostCheck: bool
    __useInterceptor: bool
    _ssoUA: str = _UAPool().get_random_ua()

    def __init__(self, service_url: str = None, time_out: int = 10, sso_host_check: bool = True,
                 sso_jump_host_check: bool = True, request_login_client: NetworkClient = None,
                 with_interceptor: bool = True):
        super(SSOClient, self).__init__()

        self.__ssoLoginUrlParam: dict = {}
        self.__requestLoginClient: SSOClient
        self._ssoPublicHeader: dict = {
            'User-Agent': self._ssoUA,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,'
                      'application/signed-exchange;v=b3',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1'
        }

        if service_url is not None:
            self.__ssoLoginUrlParam['service'] = parse.unquote(service_url)
        self.__netTimeOut = time_out
        self.__ssoHostCheck = sso_host_check
        self.__ssoJumpHostCheck = sso_jump_host_check
        self.__useInterceptor = with_interceptor
        if request_login_client is None:
            self.__requestLoginClient = self
        else:
            self.__requestLoginClient = request_login_client

    def __get_login_post_form(self, sso_html_content: str, user_id: str, user_pw: str) -> dict:
        form = {'username': user_id, 'password': user_pw}

        soup = BeautifulSoup(sso_html_content, "html.parser")
        for node in soup.find_all('input'):
            name = node.get('name')
            if name in self.__loginParam:
                form[name] = node.get('value')
        return form

    def login(self, user_id: str, user_pw: str, sso_response: Response = None) -> ClientServiceResponse:
        try:
            if sso_response is None:
                sso_response = self.__requestLoginClient.get(self.__ssoLoginUrl, with_interceptor=self.__useInterceptor,
                                                             params=self.__ssoLoginUrlParam,
                                                             timeout=self.__netTimeOut, headers=self._ssoPublicHeader)
            response = ClientServiceResponse()
            response.is_service_login = len(self.__ssoLoginUrlParam) > 0
            if self.__useInterceptor or not self.__ssoHostCheck \
                    or self._has_same_host(sso_response.url, self.__ssoLoginUrl):
                if '登录成功' in sso_response.text and \
                        '密码错误' not in sso_response.text and \
                        '请勿输入非法字符' not in sso_response.text and \
                        not response.is_service_login:
                    response.is_success = True
                else:
                    post_form = self.__get_login_post_form(sso_response.text, user_id, user_pw)
                    with self.__requestLoginClient.post(sso_response.url, post_form,
                                                        with_interceptor=self.__useInterceptor,
                                                        timeout=self.__netTimeOut,
                                                        headers=self._ssoPublicHeader) as login_result_response:

                        if (self.__useInterceptor or not self.__ssoHostCheck
                            or self._has_same_host(login_result_response.url, self.__ssoLoginUrl)) \
                                and not response.is_service_login:
                            response.is_success = '登录成功' in login_result_response.text and \
                                                  '密码错误' not in login_result_response.text and \
                                                  '请勿输入非法字符' not in login_result_response.text
                        elif self.__useInterceptor or not self.__ssoJumpHostCheck \
                                or self._has_same_host(login_result_response.url, self.__ssoLoginUrlParam['service']):
                            response.status_code = login_result_response.status_code
                            response.url = login_result_response.url
                            response.text = login_result_response.text
                            response.headers = login_result_response.headers
                            response.is_success = True
                        else:
                            raise ConnectionError('SSO service host is different from jump page host! Jump page: '
                                                  + login_result_response.url)
            elif self.__useInterceptor or not self.__ssoJumpHostCheck \
                    or self._has_same_host(sso_response.url, self.__ssoLoginUrlParam['service']):
                response.status_code = sso_response.status_code
                response.url = sso_response.url
                response.text = sso_response.text
                response.headers = sso_response.headers
                response.is_success = True
            else:
                raise ConnectionError('SSO service host is different from jump page host! Jump page: '
                                      + sso_response.url)
            return response
        finally:
            if sso_response is not None:
                sso_response.close()

    def logout(self) -> bool:
        with self.__requestLoginClient.get(self.__ssoLogoutUrl, with_interceptor=self.__useInterceptor,
                                           timeout=self.__netTimeOut,
                                           headers=self._ssoPublicHeader) as logout_response:
            if '注销成功' in logout_response.text:
                self.cookies.clear()
                return True
            return False

    def check_login(self) -> bool:
        with self.__requestLoginClient.get(self.__ssoLoginUrl, with_interceptor=self.__useInterceptor,
                                           timeout=self.__netTimeOut, headers=self._ssoPublicHeader) \
                as login_check_response:
            return self.check_login_with_response(login_check_response)

    def check_login_with_response(self, response: Response) -> bool:
        return '登录成功' in response.text or self._has_same_host(response.url, self.__ssoLoginUrl)

    @staticmethod
    def _has_same_host(url1: str, url2: str):
        return url1 is not None and url2 is not None \
               and parse.urlparse(url1).netloc.lower() == parse.urlparse(url2).netloc.lower()

    def __enter__(self):
        super(SSOClient, self).__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()
        super(SSOClient, self).__exit__(exc_type, exc_val, exc_tb)
