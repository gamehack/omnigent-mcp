import httpx
import pytest
from client import Omnigent, OmnigentError, identifier

@pytest.fixture
def mock():
    calls=[]
    def handler(r):
        calls.append(r)
        if r.url.path=='/oauth/token':
            assert b'client_credentials' in r.content
            return httpx.Response(200,json={'access_token':'fake','expires_in':3600})
        assert r.headers['authorization']=='Bearer fake'
        if r.url.path=='/v1/sessions' and r.method=='POST':
            return httpx.Response(200,json={'id':'conv_1'})
        if r.url.path=='/v1/sessions/conv_1':
            return httpx.Response(200,json={'runner_online':True,'status':'idle'})
        if r.url.path=='/v1/sessions/conv_off':
            return httpx.Response(200,json={'runner_online':False})
        return httpx.Response(200,json={'data':[]})
    return Omnigent('https://example.test','client','secret',httpx.MockTransport(handler)),calls

def test_list_and_reuse(mock):
    api,calls=mock
    api.request('GET','/v1/agents')
    api.list_sessions(10,'cursor','test')
    assert len([r for r in calls if r.url.path=='/oauth/token'])==1
    assert calls[-1].url.params['limit']=='10'
    assert calls[-1].url.params['after']=='cursor'

def test_create_send(mock):
    api,calls=mock
    assert api.create('ag_1','host_1','/tmp/project','test')['session_url']=='https://example.test/c/conv_1'
    assert api.send('conv_1','ping')['accepted']
    assert b'input_text' in calls[-1].content

def test_offline(mock):
    api,calls=mock
    with pytest.raises(OmnigentError): api.send('conv_off','ping')
    assert not any(r.url.path.endswith('/events') for r in calls)

def test_history_interrupt(mock):
    api,calls=mock
    api.history('conv_1',10,'abc')
    assert calls[-1].url.params['after']=='abc'
    api.interrupt('conv_1')
    assert b'interrupt' in calls[-1].content

def test_invalid(mock):
    api,calls=mock
    with pytest.raises(ValueError): identifier('../admin')
    with pytest.raises(ValueError): api.list_sessions(500)
    with pytest.raises(ValueError): api.send('conv_1',' ')
    assert not calls

def test_no_write_retry():
    seen=[]
    def handler(r):
        seen.append(r)
        if r.url.path=='/oauth/token': return httpx.Response(200,json={'access_token':'fake','expires_in':3600})
        return httpx.Response(401)
    api=Omnigent('https://example.test','x','y',httpx.MockTransport(handler))
    with pytest.raises(OmnigentError): api.interrupt('conv_1')
    assert len(seen)==2
