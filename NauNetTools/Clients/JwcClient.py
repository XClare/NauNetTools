from enum import IntEnum
from urllib import parse

from bs4 import BeautifulSoup, Tag
from requests import Response

from NauNetTools.Clients.SSOClient import SSOClient
from NauNetTools.Interceptors.VPNInterceptor import VPNInterceptor, VPNUtils


# For http://jwc.nau.edu.cn
class JwcNetState(IntEnum):
    # Success
    SUCCESS = 0
    # Request timeout
    TIME_OUT = 1
    # Error when login
    LOGIN_ERROR = 2
    # Already login
    ALREADY_LOGIN = 3
    # Password error
    PASSWORD_ERROR = 4
    # Server error
    SERVER_ERROR = 5
    # Request error
    REQUEST_ERROR = 6
    # Url or html parse error
    PARSE_ERROR = 7


class JwcClient(SSOClient):
    jwcServer: str = 'http://jwc.nau.edu.cn/'
    __jwcLoginUrl: str = jwcServer + 'login.aspx'
    __jwcSingleLoginUrl: str = jwcServer + 'Login_Single.aspx'
    __jwcLogoutUrl: str = jwcServer + 'LoginOut.aspx'
    __jwcStudentIndex: str = jwcServer + 'Students/StudentIndex.aspx'
    __netTimeOut: int
    __loginKeeperRecallPeriod: int = 5
    __jwcIndexUrl = None
    __jwcIndexPath = None
    __loginState: bool = False
    __lastLoginSuccessHtml = None
    avoidAlreadyLogin: bool

    def __init__(self, time_out: int = 10, avoid_already_login: bool = True):
        super(JwcClient, self).__init__(self.__jwcSingleLoginUrl, time_out)

        self.__jwcFunctionDict: dict = {}
        self._jwcPublicHeader: dict = {
            'User-Agent': self._ssoUA,
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest;'
        }

        self.__netTimeOut = time_out
        self.avoidAlreadyLogin = avoid_already_login

    def get_jwc_server(self):
        return self.jwcServer

    def get_jwc_main_url(self):
        return self.__jwcIndexUrl

    def login(self, user_id: str, user_pw: str, sso_response: Response = None) -> JwcNetState:
        return self._jwc_login(user_id, user_pw, sso_response)

    def get_last_login_success_html(self):
        return self.__lastLoginSuccessHtml

    def _jwc_login(self, user_id: str, user_pw: str, sso_response: Response = None, re_login_once: bool = False):
        # noinspection PyBroadException
        try:
            login_result = super(JwcClient, self).login(user_id, user_pw, sso_response)
            if login_result.is_success:
                if '当前你已经登录' in login_result.text:
                    if self.avoidAlreadyLogin and not re_login_once:
                        self.logout()
                        return self._jwc_login(user_id, user_pw, sso_response, True)
                    else:
                        return JwcNetState.ALREADY_LOGIN
                elif '请勿输入非法字符' in login_result.text:
                    return JwcNetState.SERVER_ERROR
                elif '密码错误' in login_result.text:
                    return JwcNetState.PASSWORD_ERROR
                else:
                    self.__loginState = True
                    self.__jwcIndexUrl = login_result.url
                    self.__lastLoginSuccessHtml = login_result.text
                    # noinspection PyBroadException
                    try:
                        self.__jwcIndexPath = self.__get_index_path(login_result.url)
                        self.__parse_jwc_function(login_result.text)
                    except:
                        return JwcNetState.PARSE_ERROR
                    else:
                        return JwcNetState.SUCCESS
            else:
                return JwcNetState.PASSWORD_ERROR
        except TimeoutError:
            return JwcNetState.TIME_OUT
        except:
            return JwcNetState.REQUEST_ERROR

    @staticmethod
    def __get_index_path(url: str) -> str:
        path = ''
        if url is not None:
            path = parse.urlparse(url).path
            if len(path) > 0:
                path = path[1:path.rindex('/') + 1]
        return path

    def __parse_jwc_function(self, content_html: str):
        if content_html is not None and not str.isspace(content_html):
            self.__jwcFunctionDict = {}
            soup = BeautifulSoup(content_html, "html.parser")
            tree = soup.find('ul', id='tt')
            self.__tree_node_selector(Tag(tree), self.__jwcFunctionDict)

    def __tree_node_selector(self, soup_node_tree: Tag, father_dict: dict):
        for li in soup_node_tree.find_all('li', recursive=False):
            ul = li.find('ul', recursive=False)
            if ul is None:
                a = li.find('a')
                father_dict[a.text] = self.__tree_node_jump_url_fix(a.attrs['href'])
            else:
                key = li.find('span').text
                father_dict[key] = {}
                self.__tree_node_selector(ul, father_dict[key])

    def __tree_node_jump_url_fix(self, href: str) -> str:
        if href is not None:
            href = href.strip()
            if 'Direct' in href:
                start = href.index('Direct')
                href = href[href.index('\'', start) + 1:href.rindex('\'', start)]
            if href.startswith('http'):
                return href
            else:
                if VPNUtils.is_use_school_vpn(self):
                    return VPNInterceptor.vpnServer + '/' + self.__jwcIndexPath + href
                else:
                    return self.jwcServer + self.__jwcIndexPath + href
        return ''

    def check_login(self) -> bool:
        if super(JwcClient, self).check_login():
            # noinspection PyBroadException
            try:
                with self.get(self.__jwcStudentIndex, timeout=self.__netTimeOut,
                              headers=self._jwcPublicHeader) as check_login_response:
                    url_parse = parse.urlparse(check_login_response.url)
                    return 'Login.aspx' not in url_parse.path and '用户登录_南京审计大学教务管理系统' not in check_login_response.text
            except:
                return False
        else:
            return False

    def check_login_with_response(self, response: Response) -> bool:
        if super(JwcClient, self).check_login_with_response(response):
            url_parse = parse.urlparse(response.url)
            return 'Login.aspx' not in url_parse.path and '用户登录_南京审计大学教务管理系统' not in response.text
        else:
            return False

    def get_function_dict(self) -> dict:
        if self.__loginState:
            return self.__jwcFunctionDict
        else:
            raise ConnectionError('You must login once first!')

    def logout(self) -> JwcNetState:
        # noinspection PyBroadException
        try:
            with self.get(self.__jwcLogoutUrl, timeout=self.__netTimeOut,
                          headers=self._jwcPublicHeader) as logout_response:
                if logout_response.url == self.__jwcLoginUrl and super(JwcClient, self).logout():
                    self.__loginState = False
                    self.__jwcIndexUrl = None
                    self.__jwcIndexPath = None
                    self.__lastLoginSuccessHtml = None
                    return JwcNetState.SUCCESS
                else:
                    return JwcNetState.SERVER_ERROR
        except TimeoutError:
            return JwcNetState.TIME_OUT
        except:
            return JwcNetState.REQUEST_ERROR

    def __enter__(self):
        super(JwcClient, self).__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()
        super(JwcClient, self).__exit__(exc_type, exc_val, exc_tb)
