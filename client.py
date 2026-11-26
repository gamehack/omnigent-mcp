import re
import time
from urllib.parse import urlsplit
from threading import Lock
import httpx

class OmnigentError(RuntimeError):
    pass

def identifier(value: str) -> str:
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,200}', value):
        raise ValueError('Invalid Omnigent identifier')
    return value

class Omnigent:
    def __init__(self, base_url, client_id, client_secret, transport=None, public_url=None):
        self.base = base_url.rstrip('/')
        self.public_url = (public_url or self.base).rstrip('/')
        url = urlsplit(self.base)
        if url.scheme not in ('http','https') or not url.netloc or url.query or url.fragment or url.username:
            raise ValueError('Invalid OMNIGENT_URL')
        if url.scheme == 'http' and url.hostname not in ('127.0.0.1','localhost','::1'):
            raise ValueError('Use HTTPS for non-loopback Omnigent endpoints')
        self.client_id, self.client_secret = client_id, client_secret
        if not client_id or not client_secret:
            raise ValueError('Machine credentials are required')
        self.http = httpx.Client(transport=transport, timeout=httpx.Timeout(20, connect=5), follow_redirects=False, trust_env=False)
        self.lock = Lock()
        self.token = None
        self.deadline = 0

    def _token(self):
        with self.lock:
            if self.token and time.monotonic() < self.deadline:
                return self.token
            try:
                r = self.http.post(self.base+'/oauth/token', data={'grant_type':'client_credentials','client_id':self.client_id,'client_secret':self.client_secret})
                r.raise_for_status()
                obj = r.json()
                self.token = obj['access_token']
                expires = float(obj.get('expires_in', 60))
                self.deadline = time.monotonic() + max(0, expires-30)
                return self.token
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                raise OmnigentError('Omnigent machine authentication failed') from None

    def request(self, method, path, *, params=None, body=None):
        token = self._token()
        try:
            r = self.http.request(method,self.base+path,headers={'Authorization':'Bearer '+token},params=params,json=body)
            # Refresh once for reads; do not replay mutation requests automatically.
            if r.status_code == 401:
                with self.lock:
                    if self.token == token:
                        self.deadline = 0
                if method == 'GET':
                    r = self.http.request(method,self.base+path,headers={'Authorization':'Bearer '+self._token()},params=params)
            if not r.is_success:
                raise OmnigentError(f'Omnigent returned HTTP {r.status_code}; verify permissions or session state')
            if not r.content:
                return {'accepted': True}
            return r.json()
        except httpx.HTTPError:
            raise OmnigentError('Omnigent network failure; for writes check session state before retrying') from None
        except ValueError:
            raise OmnigentError('Invalid Omnigent JSON response; verify server version') from None

    def session_path(self, session_id, suffix=''):
        return '/v1/sessions/'+identifier(session_id)+suffix

    def url(self, session_id):
        return self.public_url+'/c/'+identifier(session_id)

    def list_sessions(self, limit=20, after=None, search_query=None):
        if not 1 <= limit <= 50:
            raise ValueError('limit must be 1–50')
        params={'limit':limit,'sort_by':'updated_at'}
        if after: params['after']=after
        if search_query: params['search_query']=search_query
        return self.request('GET','/v1/sessions',params=params)

    def create(self, agent_id, host_id, workspace, title):
        if not workspace or not title or len(title)>200:
            raise ValueError('Workspace and title are required; title max 200')
        data=self.request('POST','/v1/sessions',body={'agent_id':identifier(agent_id),'host_id':identifier(host_id),'workspace':workspace,'title':title})
        return {'session':data,'session_url':self.url(data['id']),'next':'Check runner_online before sending a message'}

    def send(self, session_id, message):
        if not message.strip() or len(message)>32000:
            raise ValueError('Message must contain 1–32000 characters')
        path=self.session_path(session_id)
        state=self.request('GET',path)
        if state.get('runner_online') is not True:
            raise OmnigentError('Runner is not online; check session status and try later')
        result=self.request('POST',path+'/events',body={'type':'message','data':{'role':'user','content':[{'type':'input_text','text':message}]}})
        return {'accepted':True,'session_id':session_id,'session_url':self.url(session_id),'result':result,'note':'Accepted by server; not proof that execution completed'}

    def history(self, session_id, limit=20, after=None):
        if not 1 <= limit <= 50: raise ValueError('limit must be 1–50')
        params={'limit':limit}
        if after: params['after']=after
        return self.request('GET',self.session_path(session_id,'/items'),params=params)

    def interrupt(self, session_id):
        return {'session_id':session_id,'result':self.request('POST',self.session_path(session_id,'/events'),body={'type':'interrupt'}),'note':'Interrupt requested; confirm status separately'}
