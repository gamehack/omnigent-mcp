import json
import base64
import time

import httpx
import pytest

from business_api import BusinessAPI, OPERATIONS, CATALOG, path_for, openapi_path, operation
from client import Omnigent, OmnigentError

HOST = "https://omnigent.example.test"
DOC = {
    "openapi": "3.1.0",
    "info": {"title": "Omnigent", "version": "0.23.0"},
    "components": {"schemas": {"ScheduledTask": {
        "type": "object",
        "required": ["name", "prompt"],
        "properties": {"name": {"type":"string"}, "prompt": {"type":"string"}},
    }}},
    "paths": {
        "/v1/hosts": {"get": {"summary":"List hosts"}},
        "/v1/hosts/{host_id}": {"get": {"parameters":[
            {"in":"path","name":"host_id","required":True,"schema":{"type":"string"}},
            {"in":"query","name":"limit","schema":{"type":"integer","minimum":1}},
        ]}},
        "/v1/hosts/{host_id}/filesystem/{path}": {"get": {}},
        "/v1/scheduled-tasks": {"post": {"requestBody":{"required":True,"content":{
            "application/json":{"schema":{"$ref":"#/components/schemas/ScheduledTask"}}
        }}}},
        "/v1/scheduled-tasks/{scheduled_task_id}": {"delete": {}},
        "/v1/sessions/{session_id}/resources/files": {"post": {"requestBody":{
            "required":True, "content":{"multipart/form-data":{"schema":{"type":"object"}}}
        }}},
        "/v1/sessions/{session_id}/resources/files/{file_id}/content": {"get": {}},
        "/v1/sessions/{session_id}/events": {"post": {"requestBody":{"required":True}}},
        "/v1/sessions/{session_id}/resources/terminals": {"post": {}},
        "/v1/info": {"get": {}},
        "/v1/new-unknown-route": {"get": {}},
    },
}


@pytest.fixture
def setup(tmp_path):
    calls = []
    def handler(request):
        calls.append(request)
        path = request.url.path
        if path == "/openapi.json":
            return httpx.Response(200, json=DOC)
        if path == "/v1/info":
            return httpx.Response(200, json={"session_event_types":["message","interrupt"]})
        if path.endswith("/content"):
            return httpx.Response(200, content=b"test binary\x00\xff",
                                  headers={"content-type":"application/octet-stream"})
        if path == "/v1/hosts/unauthorized":
            return httpx.Response(403)
        return httpx.Response(200, json={"path":path,"method":request.method,"secret":"never-return",
                                        "payload":json.loads(request.content) if request.headers.get("content-type")=="application/json" and request.content else None})
    api = Omnigent(HOST, "test-device", tmp_path/"token.json", transport=httpx.MockTransport(handler))
    api._access_token = "test-opaque-access"
    api._access_expires_at = time.time()+3600
    return BusinessAPI(api), calls


def test_catalog_integrity():
    entries = CATALOG["operations"]
    assert len(entries) == len(OPERATIONS) == 212
    assert len({(x["method"],openapi_path(x)) for x in entries}) == len(entries)
    assert all(x["path"].startswith("/v1/") for x in entries)
    assert all(x["method"] in ("GET","POST","PUT","PATCH","DELETE") for x in entries)
    assert not any("/oauth/" in x["path"] or "/hooks/" in x["path"] for x in entries)
    assert "get_session_sign_in_link" not in OPERATIONS
    assert "run_environment_shell" not in OPERATIONS


def test_discover_and_describe(setup):
    client,calls = setup
    static = client.list_operations(domain="automation",mode="write",limit=2)
    assert static["total"] > 2 and static["next_offset"] == 2
    assert not calls
    live = client.list_operations(search="create_scheduled_task",live=True)
    assert live["operations"][0]["advertised"] is True
    desc = client.describe("create_scheduled_task")
    assert "#/components/schemas/ScheduledTask" in desc["referenced_schemas"]
    assert desc["write_confirmation_required"]
    coverage = client.coverage(live=True)
    assert coverage["catalog_operations"] == 212
    assert {"method":"GET","path":"/v1/new-unknown-route"} in coverage["live_not_cataloged"]


@pytest.mark.parametrize("value",["../x","a/b","%2f", "a?b", "a#b","a\\b","..","a\n","//evil.example"])
def test_path_injection(value):
    with pytest.raises(ValueError):
        path_for(operation("get_host"),{"host_id":value})


def test_path_converter_and_exact_arguments():
    op = operation("list_host_filesystem")
    assert path_for(op,{"host_id":"host_a","path":"a/b.txt"}) == "/v1/hosts/host_a/filesystem/a/b.txt"
    with pytest.raises(ValueError):
        path_for(op,{"host_id":"host_a","path":"a/../b"})
    with pytest.raises(ValueError):
        path_for(operation("get_host"),{"host_id":"host_a","extra":"x"})


def test_read_write_isolation_and_unknown_operation(setup):
    client,calls = setup
    with pytest.raises(PermissionError):
        client.invoke("create_scheduled_task","read")
    with pytest.raises(PermissionError):
        client.invoke("create_scheduled_task","write",body={"name":"x","prompt":"y"})
    with pytest.raises(PermissionError):
        client.invoke("get_host","write",confirm=True,path_args={"host_id":"host_a"})
    with pytest.raises(ValueError):
        client.invoke("https://other.example","read")
    assert not calls


def test_get_and_request_schema(setup):
    client,calls = setup
    with pytest.raises(ValueError):
        client.invoke("get_host","read",{"host_id":"host_a"},query={"limit":0})
    result = client.invoke("get_host","read",{"host_id":"host_a"},query={"limit":1})
    assert result["data"]["path"] == "/v1/hosts/host_a"
    assert result["data"]["secret"] == "[redacted]"
    assert calls[-1].headers["authorization"] == "Bearer test-opaque-access"
    assert calls[-1].url.params["limit"] == "1"
    with pytest.raises(OmnigentError,match="not advertised"):
        client.invoke("list_projects","read")


def test_json_mutation_and_refs(setup):
    client,calls = setup
    with pytest.raises(ValueError):
        client.invoke("create_scheduled_task","write",body={"name":"x"},confirm=True)
    with pytest.raises(ValueError):
        client.invoke("create_scheduled_task","write",body={"name":"x","prompt":"y","api_key":"s"},confirm=True)
    out = client.invoke("create_scheduled_task","write",body={"name":"x","prompt":"y"},confirm=True)
    assert out["data"]["payload"] == {"name":"x","prompt":"y"}
    assert calls[-1].method == "POST"
    assert sum(r.method=="POST" for r in calls) == 1


def test_multipart_and_binary(setup):
    client,calls = setup
    part = {"field":"file","filename":"a.txt","content_base64":base64.b64encode(b"hello").decode(),"content_type":"text/plain"}
    client.invoke("upload_session_file","write",{"session_id":"conv_1"},files=[part],confirm=True)
    assert "multipart/form-data" in calls[-1].headers["content-type"]
    assert b"hello" in calls[-1].content
    with pytest.raises(ValueError):
        client.invoke("upload_session_file","write",{"session_id":"conv_1"},files=[dict(part,field="other")],confirm=True)
    with pytest.raises(ValueError):
        client.invoke("upload_session_file","write",{"session_id":"conv_1"},files=[dict(part,content_base64="invalid!!")],confirm=True)
    result = client.invoke("get_session_file_content","read",{"session_id":"conv_1","file_id":"file_1"})
    assert result["encoding"] == "base64"
    assert base64.b64decode(result["data"]) == b"test binary\x00\xff"


def test_event_and_terminal_boundaries(setup):
    client,calls = setup
    with pytest.raises(ValueError):
        client.invoke("post_session_event","write",{"session_id":"conv_1"},body={"type":"runner_only"},confirm=True)
    with pytest.raises(ValueError):
        client.invoke("post_session_event","write",{"session_id":"conv_1"},body={"type":"message","data":{"role":"assistant"}},confirm=True)
    client.invoke("post_session_event","write",{"session_id":"conv_1"},body={"type":"interrupt"},confirm=True)
    assert calls[-1].method == "POST"
    with pytest.raises(ValueError):
        client.invoke("create_session_terminal","write",{"session_id":"conv_1"},body={"terminal":"native","ensure_native_terminal":True},confirm=True)


def test_response_limit_and_write_not_replayed(tmp_path):
    calls = []
    def handler(request):
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(401)
        return httpx.Response(200,content=b"x"*100,headers={"content-type":"text/plain"})
    api = Omnigent(HOST,"test",tmp_path/"token.json",transport=httpx.MockTransport(handler))
    api._access_token="opaque"
    api._access_expires_at=time.time()+3600
    with pytest.raises(OmnigentError,match="output limit"):
        api.request_data("GET","/v1/hosts",max_bytes=50)
    with pytest.raises(OmnigentError,match="HTTP 401"):
        api.request_data("POST","/v1/projects",body={"name":"test"})
    assert sum(r.method=="POST" for r in calls)==1


def test_denied_request_does_not_retry(setup):
    client,calls=setup
    with pytest.raises(OmnigentError,match="HTTP 403"):
        client.invoke("get_host","read",{"host_id":"unauthorized"})
    assert sum(r.url.path=="/v1/hosts/unauthorized" for r in calls)==1
