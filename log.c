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
#    response_status,
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
        url = "https://passport.jd.com/new/login.aspx"
        page = self.sess.get(url, headers=self.headers)
        return page


    def _get_QRcode(self):
        url = 'https://qr.m.jd.com/show'
        payload = {
            'appid': 133,
            'size': 147,
            't': str(int(time.time() * 1000)),
        }
       
        headers = {
            'User-Agent': self.user_agent,
            'Referer': 'https://passport.jd.com/new/login.aspx',
        }

        resp = self.sess.get(url=url, headers=headers, params=payload)
        
        if not response_status(resp):
            logger.info('获取二维码失败')
            return False

