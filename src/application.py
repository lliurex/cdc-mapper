from flask import Flask, Response, request, abort, jsonify
import ldap
from pathlib import Path
from configparser import ConfigParser
from threading import Thread, Semaphore
import time
import grp
app = Flask(__name__)

class CDC:

    def __init__(self):
        self.load_configuration()
        self.list_of_queries = {}
        try:
            sudo_gid = grp.getgrnam("sudo").gr_gid
            adm_gid = grp.getgrnam("adm").gr_gid
            self.cache_users = {"students":[10004, []], "teachers":[10003,[]], "sudo":[sudo_gid,[]], "adm": [adm_gid,[]] }
        except:
            self.cache_users = {"students":[10004, []], "teachers":[10003,[]] }
        self.users_timeout = {}
        self.semaphore = Semaphore()
    #def __init__

    @property
    def identifier(self):
        '''
            This identifier go back to 0 when list_of_queries is void. So identifier not increase to big numbers 
        '''
        result = 0
        if len(self.list_of_queries.keys()) > 0: 
            result = list(self.list_of_queries.keys())[-1]
        return result

    def load_configuration( self ):
        self.config_path = Path( "/etc/sssd/sssd.conf" )
        self.sssd_config = ConfigParser()
        if self.config_path.exists():
            self.sssd_config.read( str( self.config_path ) )
            list_gva_domains = list(filter(lambda x : "EDU.GVA.ES" in x, self.sssd_config.sections()))
            self.ldap_config = self.sssd_config[list_gva_domains[0]]
            self.base_dn = self.ldap_config["ldap_search_base"]

    #def load_configuration

    def load_connection(self):
       self.ldap = ldap.initialize( self.ldap_config[ "ldap_uri" ] )
       self.ldap.set_option( ldap.VERSION, ldap.VERSION3 )
       self.ldap.set_option( ldap.OPT_NETWORK_TIMEOUT, 20 )
       self.ldap.set_option( ldap.OPT_TIMEOUT, 20)
       self.ldap.bind_s( self.ldap_config[ "ldap_default_bind_dn" ], self.ldap_config[ "ldap_default_authtok" ] )

    def push_query( self, user ):
        '''
            Async function
            Add query in pool and return identifier for polling later
        '''
        #return query_id
        #async
        identifier = self.identifier + 1
        self.list_of_queries[identifier] = Thread(target=self._push_query, args=(user, identifier))
        self.list_of_queries[identifier].start()
        return identifier
    #def push_query


    def _push_query(self, user, identifier):
        try:
            self.load_connection()
        except ldap.SERVER_DOWN:
            del(self.list_of_queries[identifier])
            return

        # 5 minutes cache
        if user in self.users_timeout.keys() and ( self.users_timeout[user] - 300 ) <= time.time():
            del(self.list_of_queries[identifier])
            return

        self.users_timeout[user] = time.time()
        list_groups = []
        dn_user_list = [ x[0] for x in self.ldap.search_s(self.base_dn, ldap.SCOPE_SUBTREE, "(cn={name})".format(name=user),["dn"]) if x[0] is not None ]
        for dn_user in dn_user_list:
            list_groups = list_groups  + [ x[1]['cn'][0].decode('utf-8') for x in self.ldap.search_s(self.base_dn, ldap.SCOPE_SUBTREE, "(member={name})".format(name=dn_user),["cn"]) if x[0] is not None ]
        self.semaphore.acquire()
        for x in list(set(list_groups)):
            if x.lower().startswith("alu"):
                self.cache_users["students"][1].append(user)
                self.cache_users["students"][1] = list(set(self.cache_users["students"][1]))
            if x.lower().startswith("doc"):
                self.cache_users["teachers"][1].append(user)
                self.cache_users["teachers"][1] = list(set(self.cache_users["teachers"][1]))
            if "sudo" in self.cache_users.keys():
                if x.lower().startswith("adm"):
                    self.cache_users["sudo"][1].append(user)
                    self.cache_users["sudo"][1] = list(set(self.cache_users["sudo"][1]))
                    self.cache_users["adm"][1].append(user)
                    self.cache_users["adm"][1] = list(set(self.cache_users["adm"][1]))

        self.semaphore.release()
        # Remove query from list becauseof this finish
        del(self.list_of_queries[identifier])
    #def _push_query 

    def wait_for_queries(self):
        '''
            Sync function
            wait to all queries finish
        '''

        list_of_queries = list(self.list_of_queries.keys())
        for x in list_of_queries:
            if x in self.list_of_queries:
                self.list_of_queries[x].join()
        return True
    #def wait_for_queries

    def query_status(self, identifier):
        '''
            get status query
        '''
        return self.list_of_queries[identifier].is_alive()
    #def query_status

    def getgrall(self):
        '''
            Return all groups
        '''
        self.semaphore.acquire()
        self.semaphore.release()
        return self.cache_users
    #def getgrall

    def getgrgid(self, gid):
       '''
            If exists group with gid return its name
       '''
       self.semaphore.acquire()
       self.semaphore.release()
       for x in self.cache_users.keys():
            if self.cache_users[x][0] == gid:
                return x
       return -1
    #def getgrgid

    def getgrnam(self, name):
        '''
            If exists group with name return its gid
        '''
        self.semaphore.acquire()
        self.semaphore.release()
        if name in self.cache_users.keys():
            return self.cache_users[name][0]
        return -1
    #def getgrnam

    def clear_cache(self):
        for x in self.cache_users.keys():
            self.cache_users[x][1] = []
        return True
    #def clear_cache

cdc = CDC()

@app.route('/')
@app.route('/getgrall')
def getgrall():
    return jsonify(cdc.getgrall())

@app.route('/push/<username>')
def push_user(username):
    return jsonify(cdc.push_query(username))

@app.route('/wait_for_queries')
def wait_for_queries():
    return jsonify(cdc.wait_for_queries())

@app.route('/clear_cache')
def clear_cache():
    return jsonify(cdc.clear_cache())


