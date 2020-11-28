#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import os
import pickle
import re
import random
import time
import requests

from bs4 import BeautifulSoup
from config import global_config
from exception import AsstException
from log import logger
from messenger import Messenger
from timer import Timer
from util import (
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT,
    check_login,
    deprecated,
    encrypt_pwd,
#    encrypt_payment_pwd,
#    get_tag_value,
#    get_random_useragent,
#    open_image,
#    parse_area_id,
#    parse_json,
#    parse_sku_id,
#    parse_items_dict,
    response_status,
#    save_image,
#    split_area_id
)

class Assistant(object):

    def __init__(self):
        use_random_ua = global_config.getboolean('config', 'random_useragent')
        self.user_agent = DEFAULT_USER_AGENT if not use_random_ua else get_random_useragent()
        self.headers = {'User-Agent': self.user_agent}
        self.eid          = global_config.get('config', 'eid')
        self.fp           = global_config.get('config', 'fp')
        self.track_id     = global_config.get('config', 'track_id')
        self.risk_control = global_config.get('config', 'risk_control')
        if not self.eid or not self.fp or not self.track_id or not self.risk_control:
            raise AsstException('please configure eid, fp, track_id, risk_control parameters in config.ini')  
        self.timeout = float(global_config.get('config', 'timeout') or DEFAULT_TIMEOUT)
        self.send_message = global_config.getboolean('messenger', 'enable')
        self.messenger = Messenger(global_config.get('messenger', 'sckey')) if self.send_message else None

        self.item_cat = dict()
        self.item_vender_ids = dict() # 记录商家id

        self.seckill_init_info = dict()
        self.seckill_order_data = dict()
        self.seckill_url = dict()

        self.username = ''
        self.nick_name = ''
        self.is_login = False
        self.sess = requests.session()
        try:
            self._load_cookies()
        except Exception:
            pass

    def _load_cookies(self):
        cookies_file = ''
        for name in os.listdir('./cookies'):
            if name.endswith('.cookies'):
                cookies_file = './cookies/{0}'.format(name)
                break
        with open(cookies_file, 'rb') as f:
            local_cookies = pickle.load(f)
        self.sess.cookies.update(local_cookies)
        self.is_login = self._validate_cookies()

    def _save_cookies(self):
        cookies_file = './cookies/{0}.cookies'.format(self.nick_name)
        directory = os.path.dirname(cookies_file)
        if not os.path.exists(directory):
            os.makedirs(directory)
        with open(cookies_file, 'wb') as f:
            pickle.dump(self.sess.cookies, f)

    def _validate_cookies(self):
        """验证cookies是否有效（是否登陆）
        通过访问用户订单列表页进行判断：若未登录，将会重定向到登陆页面
        :return: cookies是否有效 True/False
        """
        url = 'https://order.jd.com/center/list.action'
        print (url)
        payload = {
            'rid': str(int(time.time() * 1000)),
        }
        try:
            resp = self.sess.get(url=url, params=payload, allow_redirects=False)
            if resp.status_code == requests.codes.OK:
                return True
        except Exception as e:
            logger.error(e)
        self.sess = request.session()
        return False

    def login_by_QRcode(self):
        """二维码登陆
        :return:
        """
        if self.is_login:
            logger.info('登陆成功')
            return

        self._get_login_page()

        # download QR code
        if not self._get_QRcode():
            raise AsstException('二维码下载失败')
        #

    def _get_login_page(self):
        url = "http://passport.jd.com/new/login.aspx"
        page = self.sess.get(url, headers=self.headers)
        return page


    def _get_QRcode(self):
        url = 'http://qr.m.jd.com/show'
        payload = {
            'appid': 133,
            'size': 147,
            't': str(int(time.time() * 1000)),
        }
       
        headers = {
            'User-Agent': self.user_agent,
            'Referer': 'http://passport.jd.com/new/login.aspx',
        }

        resp = self.sess.get(url=url, headers=headers, params=payload)
        
        if not response_status(resp):
            logger.info('获取二维码失败')
            return False

        
root@nkgphisprc00880:/usr1/python_script/jd-assistant# cat util.py
#!/usr/bin/env python
# -*- coding:utf-8 -*-
import functools
import json
import os
import random
import re
import warnings
from base64 import b64encode

import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5

from log import logger

RSA_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDC7kw8r6tq43pwApYvkJ5lalja
N9BZb21TAIfT/vexbobzH7Q8SUdP5uDPXEBKzOjx2L28y7Xs1d9v3tdPfKI2LR7P
AzWBmDMn8riHrDDNpUpJnlAGUqJG9ooPn8j7YNpcxCa1iybOlc2kEhmJn5uwoanQ
q+CA6agNkqly2H4j6wIDAQAB
-----END PUBLIC KEY-----"""

DEFAULT_TIMEOUT = 10

DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36'

def encrypt_pwd(password, public_key=RSA_PUBLIC_KEY):
    rsa_key = RSA.importKey(public_key)
    encryptor = Cipher_pkcs1_v1_5.new(rsa_key)
    cipher = b64encode(encryptor.encrypt(password.encode('utf-8')))
    return cipher.decode('utf-8')


#def encrypt_payment_pwd(payment_pwd):
    


def deprecated(func):
    """This decorator is used to mark functions as deprecated.
    It will result in a warning being emitted when the function is used.
    """

    @functools.wraps(func)
    def new_func(*args, **kwargs):
        warnings.simplefilter('always', DeprecationWarning) # turn off filter
        warnings.warn(
            "Call to deprecated function {}.".format(func.__name__),
            category=DeprecationWarning,
            stacklevel=2
        )
        warnings.simplefilter('default', DeprecationWarning) # reset filter
        return func(*args, **kwargs)

    return new_func



def check_login(func):
    """用户登陆态校验装饰器。若用户未登录，则调用扫描登陆"""

    @functools.wraps(func)
    def new_func(self, *args, **kwargs):
        if not self.is_login:
            logger.info("{0} 需要登陆后调用，开始扫码登陆".format(func.__name__))
            self.login_by_QRcode()
        return func(self, *args, **kwargs)

    return new_func

#get_tag_value
#get_random_useragent
#open_image
#parse_area_id
#parse_json
#parse_sku_id
#parse_items_dict
#response_status
#save_image
#split_area_id        
        
    
    
    root@nkgphisprc00880:/usr1/python_script/jd-assistant# cat main.py 
#!/usr/bin/env python
# -*- coding:utf-8 -*-
from jd_assistant import Assistant

if __name__ == '__main__':
    """
    my maotai
    """

    sku_ids = '4736323'
    area = '12_904_907_50559'
    asst = Assistant() #初始化
    asst.login_by_QRcode() #扫码登陆
#    asst.buy_item_in_stock(sku_ids=sku_ids, area=area, wait_all=False, stock_interval=5) #根据商品是否有货自动下单
#    asst.login_by_QRcode()
#    asst.clear_cart()
#    asst.add_item_to_cart(sku_ids='4736323')
#    asst.submit_order()


root@nkgphisprc00880:/usr1/python_script/jd-assistant# cat config.ini 
[account]
payment_pwd = 

[config]
eid = 2QRCKMPMH2ZHMAIXALL33RLFLM3YO6CWUZRCYCWSUTMTB5IUBUUAQDFOHAEMOUSPNDRQNNLW4SGYGZIESYSV6ISRLQ 
fp = b5d4e5a4bc936ce402120aeacaa93735
track_id = undefined
risk_control = undefined

timeout = 

random_useragent = false

[messenger]
enable = false
sckey = 
