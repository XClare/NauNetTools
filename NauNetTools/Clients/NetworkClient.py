import json as json_parse
import os
from abc import ABCMeta, abstractmethod
from threading import Lock

from requests import Response
from requests import Session


class RequestParam:
    url: str
    kwargs: dict

    def __init__(self, url: str, **kwargs):
        self.url = url
        self.kwargs = kwargs


class PostRequestParam(RequestParam):
    data = None
    json = None

    def __init__(self, url: str, data=None, json=None, **kwargs):
        super(PostRequestParam, self).__init__(url, **kwargs)
        self.data = data
        self.json = json


class NetInterceptor(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def request_intercept(self, session, request_code: int, param: RequestParam):
        pass

    @abstractmethod
    def response_intercept(self, session, request_code: int, param: RequestParam, response: Response) -> Response:
        pass

    def close(self, session):
        pass


class NetworkClient(Session):
    __requestCode = 0

    def __init__(self):
        super(NetworkClient, self).__init__()
        self.__interceptorList = []
        self.__requestCodeLock = Lock()

    # Only Support GET and POST method
    def add_interceptor(self, new_interceptor: NetInterceptor):
        for interceptor in self.__interceptorList:
            if interceptor == new_interceptor:
                return
        self.__interceptorList.append(new_interceptor)

    def remove_interceptor(self, old_interceptor: NetInterceptor):
        if old_interceptor in self.__interceptorList:
            self.__interceptorList.remove(old_interceptor)

    def has_interceptor_type(self, use_interceptor: classmethod):
        for interceptor in self.__interceptorList:
            if type(interceptor) == use_interceptor:
                return True
        return False

    def __get_new_request_code(self) -> int:
        with self.__requestCodeLock:
            self.__requestCode += 1
            return self.__requestCode

    def save_cookies_to_file(self, file_path: str = 'cookies.json') -> bool:
        # noinspection PyBroadException
        try:
            data = json_parse.dumps(self.cookies.get_dict())
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(data)
                file.flush()
            return True
        except:
            return False

    def load_cookies_from_file(self, file_path: str = 'cookies.json') -> bool:
        if os.path.isfile(file_path):
            # noinspection PyBroadException
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    data = file.read()
                    self.cookies.update(json_parse.loads(data))
                return True
            except:
                return False
        return False

    def get(self, url: str, with_interceptor: bool = True, **kwargs) -> Response:
        code = self.__get_new_request_code()
        if with_interceptor:
            param = RequestParam(url, **kwargs)
            for interceptor in self.__interceptorList:
                interceptor.request_intercept(self, code, param)
            response = super(NetworkClient, self).get(param.url, **param.kwargs)
            response.encoding = response.apparent_encoding
            for interceptor in reversed(self.__interceptorList):
                response = interceptor.response_intercept(self, code, param, response)
                response.encoding = response.apparent_encoding
            return response
        else:
            return super(NetworkClient, self).get(url, **kwargs)

    def post(self, url: str, data=None, json=None, with_interceptor: bool = True, **kwargs) -> Response:
        code = self.__get_new_request_code()
        if with_interceptor:
            param = PostRequestParam(url, data, json, **kwargs)
            for interceptor in self.__interceptorList:
                interceptor.request_intercept(self, code, param)
            response = super(NetworkClient, self).post(param.url, param.data, param.json, **param.kwargs)
            response.encoding = response.apparent_encoding
            for interceptor in reversed(self.__interceptorList):
                interceptor.response_intercept(self, code, param, response)
                response.encoding = response.apparent_encoding
            return response
        else:
            return super(NetworkClient, self).post(url, data, json, **kwargs)

    def close(self):
        for interceptor in self.__interceptorList:
            interceptor.close(self)
        super(NetworkClient, self).close()

    def __enter__(self):
        super(NetworkClient, self).__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
