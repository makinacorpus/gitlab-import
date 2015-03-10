#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
__docformat__ = 'restructuredtext en'

import re
import requests
import time
from optparse import OptionParser
import json
import os
import gitlab
import sys
import string
import random
from pprint import pformat
import logging
import unicodedata


logger = logging.getLogger('gitlab_import')
PUSH_CMD = (
    'set -x && cd {0}/{1}/{2}'
    ' && '
    'if [ "x$(git count-objects|awk \'{{print $1}}\')" != "x0" ];then'
    '  git push --force --mirror {3};'
    'fi'
)


class UserCreationError(Exception):
    '''.'''


class UserDoesNotExists(Exception):
    '''.'''


class UserCantChange(Exception):
    '''.'''


class GroupCreationError(Exception):
    '''.'''


class PushError(Exception):
    '''.'''


parser = OptionParser()

parser.add_option("-u", "--users",
                  action="append", dest="sshusers", default=[],
                  help="ssh users filter")
parser.add_option("-s", "--sshkeys",
                  action="append", dest="sshkeys", default=[],
                  help="sshkeys")
parser.add_option("-t", "--token",
                  action="store", dest="token", default="",
                  help="Gitlab API Token")
parser.add_option("-l", "--loglevel",
                  action="store", dest="loglevel", default="INFO",
                  help="LOGLEVEL")
parser.add_option("-r", "--rloglevel",
                  action="store", dest="rloglevel", default="ERROR",
                  help="requests LOGLEVEL")
parser.add_option("-a", "--api",
                  action="store", dest="api",
                  default="https://gitlab.makina-corpus.net",
                  help="Gitlab API endpoint")


def get_gitlab(api, token):
    return gitlab.Gitlab(api, token=token)


def generate_password(length=16):
    characters = string.ascii_letters + string.digits
    password = "".join(random.choice(characters)
                       for x in range(length))
    return password


def asciize(uch):
    return unicodedata.normalize('NFKD', uch).encode('ascii', 'ignore')


def get_lk_part(lk, part='next'):
    matching = re.compile('<(?P<m>[^>]+)>; rel="{0}"'.format(part))
    match = matching.search(lk)
    if match:
        lk = match.groupdict()['m']
    return lk


def getgroups(self, group_id=None, page=1, per_page=20):
    '''
    Retrieve group information
    (patch original version to support pagination)

    :param group_id: Specify a group. Otherwise, all groups are returned
    :return: list of groups
    '''
    data = {'page': page, 'per_page': per_page}
    request = requests.get("{}/{}".format(self.groups_url,
                                          group_id if group_id else ""),
                           params=data, headers=self.headers,
                           verify=self.verify_ssl)
    if request.status_code == 200:
        groups = json.loads(request.content.decode("utf-8"))
        cont = True
        while cont:
            try:
                lk = request.headers['link']
                if 'next' in lk:
                    url = get_lk_part(lk)
                    request = requests.get(url,
                                           headers=self.headers,
                                           verify=self.verify_ssl)
                    if request.status_code == 200:
                        groups.extend(
                            json.loads(request.content.decode("utf-8")))
                        cont = False
                    else:
                        return False
                else:
                    cont = False
            except KeyError:
                cont = False
        return groups
    else:
        return False


def getusers(self, search=None, page=1, per_page=20):
    '''
    Retrieve user information
    (patch original version to support pagination)

    :param user_id: Specify a user. Otherwise, all users are returned
    :return: list of users
    '''
    data = {'page': page, 'per_page': per_page}
    if search:
        data['search'] = search
    request = requests.get(self.users_url, params=data,
                            headers=self.headers, verify=self.verify_ssl)
    if request.status_code == 200:
        users = json.loads(request.content.decode("utf-8"))
        cont = True
        while cont:
            try:
                lk = request.headers['link']
                if 'next' in lk:
                    url = get_lk_part(lk)
                    request = requests.get(url,
                                           headers=self.headers,
                                           verify=self.verify_ssl)
                    if request.status_code == 200:
                        users.extend(
                            json.loads(request.content.decode("utf-8")))
                        cont = False
                    else:
                        return False
                else:
                    cont = False
            except KeyError:
                cont = False
        return users
    else:
        return False


_groups = {}
def cachedgroups(gl, key='g'):
    if _groups.get(key) is None:
        _groups[key] = getgroups(gl, per_page=1000000)
    return _groups[key]


def get_user(gl, login):
    '''
    Avoid shadowing a group namespace with a user login
    '''
    groups = [a for a in cachedgroups(gl) if a['path'] == login]
    if groups:
        login = 'u' + login
        logger.info('Renaming user to {0}'.format(login))
    guser = None
    gusers = [a for a in getusers(gl, search=login, per_page=1000000)
              if a['username'] == login]
    if gusers and isinstance(gusers, list):
        guser = gusers[0]
    return login, guser


def manage_ssh_keys(gl, keys, fusers=None):
    '''
    Register ssh keys for users
    Wait for a json list in the form::
     [
      {
        "login": "admin",
        "ssh_keys": [
          "ssh-rsa AAAAB3Nzxxxx== kiorky@judith"
        ]
      }]
    '''
    done = {}
    ruser = gl.currentuser()
    if not fusers:
        fusers = []
    for user in getusers(gl, per_page=100000):
        if fusers and not (user['username'] in fusers
                           or user['email'] in fusers):
            logger.info('Skip {0}'.format(user['username']))
            continue
        try:
            login, guser = get_user(gl, user['username'])
        except:
            logger.info('pb with {0}'.format(pformat(user)))
            raise
            continue
        if not guser:
            raise UserDoesNotExists(pformat(user))
        gl.setsudo(guser['id'])
        cuser = gl.currentuser()
        if cuser['username'] != login:
            raise UserCantChange('Cant change to {0}'.format(login))
        csshkeys = gl.getsshkeys(per_page=10000)
        if not csshkeys:
            csshkeys = []
        for key in csshkeys:
            found = False
            for match in keys:
                if match.lower() in key['key'].lower():
                    found = True
                elif match.lower() in key['title'].lower():
                    found = True
            if found:
                logger.info('Removing {0}'.format(pformat(key)))
                gl.deletesshkey(key['id'])
                done[key['id']] = key
        gl.setsudo(None)
        cuser = gl.currentuser()
        if cuser['username'] != ruser['username']:
            raise UserCantChange(
                'Cant change to {0}'.format(ruser['username']))
    return done


def main():
    (options, args) = parser.parse_args()
    fmt = '%(asctime)s - %(name)s - %(levelname)s: %(message)s'
    logging.basicConfig(level=logging.getLevelName(options.loglevel.upper()),
                        format=fmt)
    logging.getLogger("requests").setLevel(
        logging.getLevelName(options.rloglevel.upper()))
    if not options.sshkeys:
        return
    gl = get_gitlab(options.api, options.token)
    ret = manage_ssh_keys(gl, options.sshkeys, options.sshusers)
    logger.debug('ret:\n{0}'.format(pformat(ret)))
    return json.dumps(ret)


if __name__ == '__main__':
    main()
# vim:set et sts=4 ts=4 tw=80:
