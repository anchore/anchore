import os
import sys
import json
import requests
import base64
import urllib

def anchore_auth_init(username, password, auth_file, client_info_url, token_url, conn_timeout, max_retries):
    if not username or not password or not auth_file or not client_info_url or not token_url or not conn_timeout or not max_retries:
        return(False)

    #'token_url':'https://ancho.re/oauth/token',
    #'client_info_url':'https://ancho.re/v1/account/users',
    anchore_auth = {'username':'', 
                    'password':'',
                    'max_retries':max_retries,
                    'conn_timeout':conn_timeout,
                    'client_info_url':client_info_url,
                    'token_url':token_url,
                    'auth_file':auth_file,
                    'client_info':{},
                    'token_info':{}
                }

    if os.path.exists(auth_file):
        #print "using existing auth tokens"
        try:
            with open(auth_file, 'r') as FH:
                loaded_anchore_auth = json.loads(FH.read())
                anchore_auth.update(loaded_anchore_auth)
        except:
            pass

    if anchore_auth['username'] != username or anchore_auth['password'] != password:
        #print "invalidating exiting token: u/p reset"
        anchore_auth['username'] = username
        anchore_auth['password'] = password
        anchore_auth_invalidate(anchore_auth)

    anchore_auth_save(anchore_auth, auth_file)

    return(anchore_auth)

def anchore_auth_invalidate(anchore_auth):
    if 'client_info' in anchore_auth:
        anchore_auth['client_info'] = {}

    if 'token_info' in anchore_auth:
        anchore_auth['token_info'] = {}

    return(True)

def anchore_auth_save(anchore_auth, auth_file):
    if not anchore_auth or not auth_file:
        return(False)

    #print "saving new anchore auth"
    try:
        with os.fdopen(os.open(auth_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0600), 'w') as OFH:
            OFH.write(json.dumps(anchore_auth))
    except:
        return(False)

    return(True)

def anchore_auth_refresh(anchore_auth, forcerefresh=False):
    if not anchore_auth:
        return(False)

    new_anchore_auth = {}
    new_anchore_auth.update(anchore_auth)
    
    username = anchore_auth['username']
    password = anchore_auth['password']
    url_username = urllib.quote_plus(username)
    url_password = urllib.quote_plus(password)
    client_info_url = anchore_auth['client_info_url']
    token_url = anchore_auth['token_url']
    client_info = anchore_auth['client_info']
    token_info = anchore_auth['token_info']
    auth_file = anchore_auth['auth_file']
    conn_timeout = anchore_auth['conn_timeout']

    if not client_info:
        # get client info
        url = client_info_url+"/"+username
        headers = {'x-anchore-password':password}
        try:
            r = requests.get(url, headers=headers, timeout=conn_timeout)
        except:
            #print "request timed out"
            return(False)

        if r.status_code == 200:
            new_anchore_auth['client_info'] = json.loads(r.text)['clients'][0]
            client_info = new_anchore_auth['client_info']
        elif r.status_code == 401:
            #print "bad username/password!"
            return(False)
        else:
            #print "unknown login error: "
            #print r.text
            return(False)

    else:
        pass
        #print "skipping client_info get"

    b64bearertok = base64.b64encode(client_info['client_id'] + ":" + client_info['client_secret'])

    if not token_info:
        # get a token set
        payload = "grant_type=password&username="+url_username+"&password="+url_password
        headers = {
            'content-type': "application/x-www-form-urlencoded",
            'authorization': "Basic " + b64bearertok,
            'cache-control': "no-cache",
            }
        try:
            r = requests.post(token_url, headers=headers, data=payload)
        except:
            #print "request timed out"
            return(False)

        if r.status_code == 200:
            new_anchore_auth['token_info'] = json.loads(r.text)
        else:
            #print "unknown token get error: "
            #print r.text
            return(False)

    elif forcerefresh:
        #print "refreshening"
        payload = "grant_type=refresh_token&refresh_token="+token_info['refreshToken']
        headers = {
            'content-type': "application/x-www-form-urlencoded",
            'authorization': "Basic " + b64bearertok,
            'cache-control': "no-cache",
            }
        try:
            r = requests.post(token_url, headers=headers, data=payload)
        except:
            #print "request timed out"
            return(False)

        if r.status_code == 200:
            new_anchore_auth['token_info'] = json.loads(r.text)
        else:
            #print "refresh token invalid"
            return(False)

    else:
        pass
        #print "skipping token_info get"

    if anchore_auth != new_anchore_auth:
        anchore_auth.update(new_anchore_auth)
        anchore_auth_save(anchore_auth, auth_file)
    else:
        pass
        #print "skipping save"

    return(True)

def anchore_auth_get(anchore_auth, url, timeout=None):
    # make a request
    print "GET URL: " + url
    if not timeout:
        timeout = anchore_auth['conn_timeout']

    ret = {'status_code':1, 'text':'', 'success':False}
    try:
        success = False
        count = 0
        max_retries = anchore_auth['max_retries']
        while(not success and count < max_retries):
            count += 1
            if not anchore_auth_refresh(anchore_auth, forcerefresh=False):
                #print "cannot get valid auth token"
                ret['text'] = "auth_failure"
                return(ret)
            else:
                token_info = anchore_auth['token_info']
                accessToken = token_info['accessToken']
                headers = {"Authorization":"Bearer " + accessToken, "Cache-Control":"no-cache"}

                r = requests.get(url, headers=headers, timeout=timeout)
                if r.status_code == 401:
                    resp = json.loads(r.text)
                    if resp['name'] == 'invalid_token':
                        #print "bad tok - attempting to refresh"
                        if not anchore_auth_refresh(anchore_auth, forcerefresh=True):
                            # start over and retry
                            #print "refresh token failed, invalidating tok and starting over"
                            anchore_auth_invalidate(anchore_auth)

                elif r.status_code == 200:
                    success = True
                    ret['success'] = True
                elif r.status_code == 404:
                    success = True
                    ret['success'] = False

                ret['status_code'] = r.status_code
                ret['text'] = r.text

    except requests.exceptions.ConnectTimeout as err:
        #print "get request timed out"
        ret['text'] = "timed_out"
        return(ret)
    except Exception as err:
        ret['text'] = str(err)
        return(ret)

    return(ret)
