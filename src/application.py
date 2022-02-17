from flask import Flask, Response, request, abort, jsonify
import ldap
import json
from pathlib import Path
from configparser import ConfigParser
from threading import Thread, Semaphore
from copy import deepcopy
import time
import grp
from apscheduler.schedulers.background import BackgroundScheduler
app = Flask(__name__)

class CDC:

    def __init__(self):
        # initialize variables
        self.cache_file = Path('/var/cache/cdc_mapper/cache')
        self.list_of_queries = {}
        self.users_timeout = {}
        self.cache_users = {}
        self.read_lock = Semaphore()
        self.read_lock_counter = 0
        self.write_lock = Semaphore()
        self.write_file_lock = Semaphore()

        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self.load_configuration()

        self.init_group("students",10004)
        self.init_group("teachers",10003)
        self.init_group("sudo")
        self.init_group("adm")
        self.load_cache()
        
    #def __init__

    def acquire_read_lock(self):
        self.read_lock.acquire()
        self.read_lock_counter += 1
        if self.read_lock_counter == 1:
            self.write_lock.acquire()
        self.read_lock.release()

    def release_read_lock(self):
        self.read_lock.acquire()
        self.read_lock_counter -= 1
        if self.read_lock_counter == 0:
            self.write_lock.release()
        self.read_lock.release()

    
    def init_group(self, name, default_id=None):
        try:
            candidate_gid = grp.getgrnam(name).gr_gid
        except:
            if default_id is not None:
                candidate_gid = default_id
            else:
                return 
        self.write_lock.acquire()
        self.cache_users[name] = [candidate_gid,[]]
        self.write_lock.release()
    #def init_group

    def load_cache(self):
        if not self.cache_file.exists():
            return 
        with self.cache_file.open("r") as fd:
            cache_data = json.load(fd)
        self.write_lock.acquire()
        for x in cache_data["groups"].keys():
            if x in self.cache_users.keys():
                self.cache_users[x][1] = cache_data["groups"][x][1]
            else:
                self.cache_users[x] = cache_data["groups"][x]
        self.users_timeout = cache_data["timeouts"]
        self.write_lock.release()
    #def load_cache


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


    def user_in_cache(self, user):
        # 5 minutes cache
        user_in_list = user in self.users_timeout.keys()
        if not user_in_list:
            return user_in_list
        self.acquire_read_lock()
        last_login_in_time = self.users_timeout[user]["time"]  >= ( time.time() - 300 )
        self.release_read_lock()
        return last_login_in_time

    def clean_user_from_groups(self, user):
        self.write_lock.acquire()
        for x in self.cache_users.keys():
            if user in self.cache_users[x][1]:
                self.cache_users[x][1].remove(user)
        self.write_lock.release()

    def _push_query(self, user, identifier):
        if self.user_in_cache(user):
            del(self.list_of_queries[identifier])
            return

        self.write_lock.acquire()
        self.users_timeout[user] = {"time":time.time(), "state":"login"}
        self.write_lock.release()

        self.save_cache()
        try:
            self.load_connection()
        except ldap.SERVER_DOWN:
            del(self.list_of_queries[identifier])
            return

        self.clean_user_from_groups(user)
        list_groups = []
        dn_user_list = [ x[0] for x in self.ldap.search_s(self.base_dn, ldap.SCOPE_SUBTREE, "(cn={name})".format(name=user),["dn"]) if x[0] is not None ]
        for dn_user in dn_user_list:
            list_groups = list_groups  + [ x[1]['cn'][0].decode('utf-8') for x in self.ldap.search_s(self.base_dn, ldap.SCOPE_SUBTREE, "(member={name})".format(name=dn_user),["cn"]) if x[0] is not None ]
        self.write_lock.acquire()
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

        self.write_lock.release()
        self.save_cache()
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
        self.acquire_read_lock()
        result = deepcopy(self.cache_users)
        self.release_read_lock()
        return result
    #def getgrall

    def getgrgid(self, gid):
       '''
            If exists group with gid return its name
       '''
       result = -1
       self.acquire_read_lock()
       for x in self.cache_users.keys():
            if self.cache_users[x][0] == gid:
                result = x
                break
       self.release_read_lock()
       return result
    #def getgrgid

    def getgrnam(self, name):
        '''
            If exists group with name return its gid
        '''
        result = -1
        self.acquire_read_lock()
        if name in self.cache_users.keys():
            result = self.cache_users[name][0]
        self.release_read_lock()
        return result
    #def getgrnam

    def clear_cache(self):
        self.write_lock.acquire()
        for x in self.cache_users.keys():
            self.cache_users[x][1] = []
        self.write_lock.release()
        return True
    #def clear_cache

    def save_cache(self):
        self.acquire_read_lock()
        self.write_file_lock.acquire()
        with self.cache_file.open("w") as fd:
            json.dump({"groups":self.cache_users, "timeouts":self.users_timeout},fd)
        self.write_file_lock.release()
        self.release_read_lock()
    
cdc = CDC()
scheduler = BackgroundScheduler()
scheduler.add_job(func=cdc.save_cache, trigger="interval", minutes=10)
scheduler.start()

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


