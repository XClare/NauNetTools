from urllib import parse

# noinspection PyProtectedMember
from bs4 import BeautifulSoup, Tag
from requests import Response

from NauNetTools.Clients.SSOClient import SSOClient
from NauNetTools.Interceptors.VPNInterceptor import VPNInterceptor, VPNUtils


class AlstuClient(SSOClient):
    alstuHost = 'alstu.nau.edu.cn'
    alstuServer = 'http://' + alstuHost + '/'
    vpnInterceptor = None
    __alstuMainUrl = alstuServer + 'default.aspx'
    __loginState: bool = False
    __useVPN: bool = True
    __lastLoginSuccessHtml = None

    def __init__(self, time_out: int = 10, use_vpn: bool = True):
        super(AlstuClient, self).__init__(self.__alstuMainUrl, time_out)

        self.__alstuFunctionDict: dict = {}

        self.__useVPN = use_vpn

    def login(self, user_id: str, user_pw: str, sso_response: Response = None) -> bool:
        if self.__useVPN:
            interceptor = VPNUtils.use_school_vpn(self, user_id, user_pw)
            if interceptor is not None:
                self.vpnInterceptor = interceptor
        login_result = super(AlstuClient, self).login(user_id, user_pw, sso_response)
        if login_result.is_success and '奥蓝信息系统' in login_result.text:
            self.__loginState = True
            self.__lastLoginSuccessHtml = login_result.text
            # noinspection PyBroadException
            try:
                self.__parse_alstu_function(login_result.text)
            except:
                return False
            else:
                return True
        else:
            self.__loginState = False
            return False

    def get_last_login_success_html(self):
        return self.__lastLoginSuccessHtml

    def __parse_alstu_function(self, content_html: str):
        if content_html is not None and not str.isspace(content_html):
            self.__alstuFunctionDict = {}
            soup = BeautifulSoup(content_html, "html.parser")
            div_node = Tag(soup.find('div', attrs={'class': 'top_nav'}))
            a_nodes = div_node.find_all('a')
            for a in a_nodes:
                self.__alstuFunctionDict[a.text] = self.__function_dict_jump_url_fix(a.attrs['href'])

    def __function_dict_jump_url_fix(self, href: str) -> str:
        if href is not None:
            href = href.strip()
            if self.__useVPN and VPNInterceptor.vpnHost == parse.urlparse(href).netloc:
                return href
            else:
                return self.alstuServer + href
        return ''

    def get_function_dict(self) -> dict:
        if self.__loginState:
            return self.__alstuFunctionDict
        else:
            raise ConnectionError('You must login once first!')

    def logout(self) -> bool:
        logout_result = super(AlstuClient, self).logout()
        if logout_result:
            self.__loginState = False
            self.__lastLoginSuccessHtml = None
            return True
        return False
