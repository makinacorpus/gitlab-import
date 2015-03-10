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
parser.add_option("-d", "--directory", dest="directory",
                  default="/srv/projects/gitlab/data/gitorious",
                  help="Gitlab import directory")
parser.add_option("-u", "--users",
                  action="store_true", dest="users", default=False,
                  help="Import users")
parser.add_option("--do-not-update-group-members",
                  action="store_false", dest="update_group_members",
                  default=True)
parser.add_option("--do-not-update-repositories",
                  action="store_false", dest="update_repositories",
                  default=True)
parser.add_option("--do-not-update-group-readers",
                  action="store_false", dest="update_group_readers",
                  default=True)
parser.add_option("--push-repositories",
                  action="store_true", dest="push_repositories",
                  default=False)
parser.add_option("-s", "--sshkeys",
                  action="store_true", dest="sshkeys", default=False,
                  help="Import sshkeys")
parser.add_option("-p", "--projects",
                  action="store_true", dest="projects", default=False,
                  help="Import projects layout")
parser.add_option("-g", "--gprojects",
                  action="store_true", dest="gprojects", default=False,
                  help="Push projects")
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


def get_user(gl, login):
    '''
    Avoid shadowing a group namespace with a user login
    '''
    groups = [a for a in getgroups(gl, per_page=1000000)
              if a['path'] == login]
    if groups:
        login = 'u' + login
        logger.info('Renaming user to {0}'.format(login))
    guser = None
    gusers = [a for a in gl.getusers(search=login, per_page=1000000)
              if a['username'] == login]
    if gusers and isinstance(gusers, list):
        guser = gusers[0]
    return login, guser


def import_ssh_keys(gl, users):
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
    for user in users:
        if not user['ssh_keys']:
            continue
        if user['login'] in ['admin', 'makina']:
            continue
        login, guser = get_user(gl, user['login'])
        user['login'] = login
        if not guser:
            raise UserDoesNotExists(pformat(user))
        gl.setsudo(guser['id'])
        cuser = gl.currentuser()
        if cuser['username'] != login:
            raise UserCantChange('Cant change to {0}'.format(login))
        csshkeys = gl.getsshkeys(per_page=10000)
        for i, k in enumerate(user['ssh_keys']):
            ti = "{0}{1}".format(k.split()[-1], i)
            if csshkeys and (k in [c['key'] for c in csshkeys]):
                logger.info('{0} already registered for {1}'.format(ti, login))
                continue
            key = gl.addsshkey(ti, k)
            if key:
                tdone = done.setdefault(login, [])
                logger.info('{0} registered for {1}'.format(ti, login))
                tdone.append(k)
        gl.setsudo(None)
        cuser = gl.currentuser()
        if cuser['username'] != ruser['username']:
            raise UserCantChange(
                'Cant change to {0}'.format(ruser['username']))
    return done


def import_users(gl, users):
    '''
    Register  users
    Wait for a json list in the form::
     [
      {
        "login": "admin",
        "email": "xxx@a.com",
        "fullname": "xxx aaa",
        "ssh_keys": [
          "ssh-rsa AAAAB3Nzxxxx== kiorky@judith"
        ]
      }]
    '''
    done = []
    for user in users:
        if user['login'] in ['admin', 'makina']:
            continue
        login, guser = get_user(gl, user['login'])
        user['login'] = login
        mail = user['email'].replace(u'\xe9', u'e')
        if guser:
            logger.info('Already existing {0}'.format(login))
        else:
            kwargs = dict(name=user['fullname'] or login,
                          username=login,
                          password=generate_password(),
                          projects_limit=100000000,
                          state='active',
                          can_create_group=True,
                          can_create_project=True,
                          email=mail)
            if len(login) in [3]:
                kwargs['provider'] = 'ldapmain'
                kwargs['extern_uid'] = (
                    u'uid={0},ou=People,dc=mcjam,dc=org'.format(login))
            logger.info('Creating {0}:\n {1}'.format(login, pformat(kwargs)))
            guser = gl.createuser(**kwargs)
            if not guser:
                raise UserCreationError(pformat(user))
        done.append(guser)
    return done


def import_projects(gl,
                    projects,
                    directory,
                    update_repositories=True,
                    push_repositories=False,
                    update_group_members=True,
                    update_group_readers=True):
    '''
    Register  projects/repos structure
    Wait for a json list in the form::

        [
         {
           "slug": "xxx",
           "owner_id": "root",
           "description": "projet xxx",
           "title": "xxx Experts",
           "repositories": [
             [
               {
                 "name": "xcg",
                 "commiters": [
                   "admin",
                   "foo",
                 ],
                 "owner_id": "root",
                 "readers": [
                     "bar"
                 ],
                 "description": "",
                 "clone_url": "git://gitorious.xxx.net/yyy/xxx.git",
                 "owner_type": "User"
               }
             ]
           ]
         }
        ]
    '''
    done = []
    for project in projects:
        gdone = {'group': None, 'perms': {}, "repos": {}, "pushed": {}}
        slug = project['slug'].replace('_', '-')
        slug = project['slug']
        groups = [a for a in getgroups(gl, per_page=1000000)
                  if a['path'] == slug]
        group = None
        if groups:
            group = groups[0]
            logger.info('Already existing group {0}'.format(group['name']))
        if not group:
            logger.info('Creating {0}'.format(slug))
            group = gl.creategroup(asciize(project['title']),
                                   asciize(slug))
            if isinstance(group, gitlab.exceptions.HttpError):
                group = gl.creategroup(asciize(slug), asciize(slug))
            if isinstance(group, gitlab.exceptions.HttpError) or not group:
                raise GroupCreationError(pformat(project))
            logger.info('Created group {0}'.format(group['name']))
            gdone['group'] = group
        for repol in project['repositories']:
            changed = False
            for ix, repo in enumerate(repol):
                if ix == 0 or (ix > 0 and changed):
                    members = getgroupmembers(gl, group['id'])
                changed = False
                #
                commiters = repo['commiters']
                if not update_group_members:
                    commiters = []
                for commiter in commiters:
                    if (
                        commiter in gdone['perms']
                        or commiter in [a['username'] for a in members]
                    ):
                        logger.info(
                            'PERM: {0}/{1} -> master '
                            'already done'.format(group['name'], commiter))
                        continue
                    login, user = get_user(gl, commiter)
                    if user:
                        if (
                            login in gdone['perms']
                            or login in [a['username'] for a in members]
                        ):
                            logger.info(
                                'PERM: {0}/{1} -> master '
                                'already done'.format(group['name'],
                                                      user['username']))
                            continue
                        logger.info(
                            'PERM: {0}/{1} -> master'.format(group['name'],
                                                             user['username']))
                        gl.addgroupmember(group['id'], user['id'], "master")
                        gdone['perms'][user['id']] = 'master'
                        changed = True
                #
                readers = repo['readers']
                if not update_group_members:
                    readers = []
                for reader in readers:
                    if (
                        reader in gdone['perms']
                        or reader in [a['username'] for a in members]
                    ):
                        logger.info(
                            'PERM: {0}/{1} -> master '
                            'already done'.format(group['name'], reader))
                        continue
                    login, user = get_user(gl, reader)
                    if user:
                        if (
                            login in gdone['perms']
                            or login in [a['username'] for a in members]
                        ):
                            logger.info(
                                'PERM: {0}/{1} -> master '
                                'already done'.format(group['name'],
                                                      user['username']))
                            continue
                        logger.info(
                            'PERM: {0}/{1} -> master'.format(group['name'],
                                                             user['username']))
                        gl.addgroupmember(group['id'], user['id'], "reporter")
                        gdone['perms'][user['id']] = 'reporter'
                        changed = True
                #
                if update_repositories or push_repositories:
                    gproject = gdone['repos'].get(repo['name'])
                    if not gproject:
                        gproject = getproject(
                            gl, repo['name'], group=group['name'])
                        if gproject:
                            logger.info('Already existing repo {0}'.format(
                                repo['name']))
                    else:
                        logger.info('Already done repo {0}'.format(
                            repo['name']))
                    if not gproject:
                        logger.info('Creating {0}'.format(repo['name']))
                        gproject = gl.createproject(
                            repo['name'],
                            namespace_id=group['id'],
                            description=repo['description'])
                    if gproject:
                        gdone['repos'][repo['name']] = gproject
                    if (
                        push_repositories
                        and repo['name'] not in gdone['pushed']
                    ):
                        cmd = PUSH_CMD.format(directory,
                                              project['slug'],
                                              repo['name'],
                                              gproject['ssh_url_to_repo'])
                        logger.info('Pushing {0}/{1} ({2})'.format(
                            group['path'], repo['name'], cmd))
                        ret = os.system(cmd)
                        if ret:
                            raise PushError('{0} failed'.format(cmd))
                        gdone['pushed'][repo['name']] = gproject
        done.append(group)
    return done


def get_lk_part(lk, part='next'):
    matching = re.compile('<(?P<m>[^>]+)>; rel="{0}"'.format(part))
    match = matching.search(lk)
    if match:
        lk = match.groupdict()['m']
    return lk


def _getprojectsingroup(self, group=None, page=1, per_page=100):
    """Returns a dictionary of all the projects for admins only
    (patch original version to support pagination)

    :return: list with the repo name,
             description, last activity,web url,
             ssh url, owner and if its public
    """
    data = {'page': page, 'per_page': per_page}

    request = requests.get("{}/all".format(self.projects_url), params=data,
                           headers=self.headers, verify=self.verify_ssl)
    if request.status_code == 200:
        projects = json.loads(request.content.decode("utf-8"))
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
                        projects.extend(json.loads(
                            request.content.decode("utf-8")))
                    else:
                        return False
                else:
                    cont = False
            except KeyError:
                cont = False
        if group:
            projects = [p for p in projects
                        if p['namespace']['name'] == group]

        return projects
    else:
        return False


def getprojectsingroup(self, group=None, page=1, per_page=100):
    projects = None
    for i in range(10):
        if not projects:
            projects = _getprojectsingroup(
                self, group=group, page=page, per_page=per_page)
        if not projects:
            logger.debug('Retrying projects call (empty)')
            time.sleep(0.05)
        else:
            break
    return projects


def getproject(self, project, group=None, page=1, per_page=100):
    gproject, projects = None, None
    groupprojects = getprojectsingroup(self, group=group)
    projects = [a for a in groupprojects if a['name'] == project]
    if projects and isinstance(projects, list):
        gproject = projects[0]
    return gproject


def getgroupmembers(self, group_id, page=1, per_page=100):
    """Lists the members of a given group id
    (patch original version to support pagination)

    :param group_id: the group id
    :param page: which page to return (default is 1)
    :param per_page: number of items to return per page (default is 20)
    :return: the group's members
    """
    data = {'page': page, 'per_page': per_page}
    request = requests.get(
        "{}/{}/members".format(self.groups_url, group_id), params=data,
        headers=self.headers, verify=self.verify_ssl)
    if request.status_code == 200:
        members = json.loads(request.content.decode("utf-8"))
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
                        members.extend(
                            json.loads(request.content.decode("utf-8")))
                        cont = False
                    else:
                        return False
                else:
                    cont = False
            except KeyError:
                cont = False
        return members
    else:
        return False


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


def main():
    (options, args) = parser.parse_args()
    fmt = '%(asctime)s - %(name)s - %(levelname)s: %(message)s'
    logging.basicConfig(level=logging.getLevelName(options.loglevel.upper()),
                        format=fmt)
    logging.getLogger("requests").setLevel(
        logging.getLevelName(options.rloglevel.upper()))
    todo = (options.users
            or options.projects
            or options.sshkeys)
    if not todo:
        return
    jproj = None
    jusers = None
    gl = get_gitlab(options.api, options.token)
    users, sshkeys, projects, gprojects = None, None, None, None
    with open(os.path.join(options.directory, "export.json")) as fic:
        jproj = json.loads(fic.read())
    with open(os.path.join(options.directory, "users.json")) as fic:
        jusers = json.loads(fic.read())
    if options.projects:
        projects = import_projects(
            gl,
            jproj,
            directory=options.directory,
            push_repositories=options.push_repositories,
            update_repositories=options.update_repositories,
            update_group_readers=options.update_group_readers,
            update_group_members=options.update_group_members)
    if options.users:
        users = import_users(gl, jusers)
    if options.sshkeys:
        sshkeys = import_ssh_keys(gl, jusers)
    ret = {'users': users,
           'projects': projects,
           'gprojects': gprojects,
           'ssh': sshkeys}
    logger.debug('ret:\n{0}'.format(pformat(ret)))
    return json.dumps(ret)


if __name__ == '__main__':
    main()
# vim:set et sts=4 ts=4 tw=80:
