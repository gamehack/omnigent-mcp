"""Explicit, pinned Omnigent business operation catalog.

No caller-controlled HTTP method, URL, headers or arbitrary endpoint. The live
OpenAPI document determines availability and request schemas; upstream still
enforces account, feature and resource permissions.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from jsonschema import Draft202012Validator, RefResolver
from jsonschema.exceptions import ValidationError

from client import Omnigent, OmnigentError

CATALOG = json.loads(Path(__file__).with_name("operations.json").read_text(encoding="utf-8"))
OPERATIONS = {op["id"]: op for op in CATALOG["operations"]}
DOMAINS = sorted({op["domain"] for op in OPERATIONS.values()})
PATH_PARAMETER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)(:path)?\}")
FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,100}$")
MAX_UPLOAD = 2 * 1024 * 1024
MAX_JSON = 1024 * 1024
MAX_RESULT = 350_000
MAX_SPEC = 16 * 1024 * 1024
# These are verified hand-parsed multipart contracts in v0.23.0 source.
MULTIPART_OVERRIDES = {
    "install_agent": {"files": {"bundle"}, "required_files": {"bundle"}, "fields": set()},
    "create_session": {"files": {"bundle", "initial_files"}, "required_files": set(), "fields": {"metadata"}},
    "upload_session_file": {"files": {"file"}, "required_files": {"file"}, "fields": set()},
    "upload_session_github_attachment": {"files": {"file"}, "required_files": {"file"}, "fields": {"pr_url"}},
}
REDACT_KEYS = {
    "access_token", "refresh_token", "client_secret", "device_code", "id_token",
    "api_key", "apikey", "password", "password_hash", "secret", "authorization",
    "authorization_header", "private_key", "cookie", "set_cookie", "runner_token",
    "tunnel_token", "binding_token", "credential_value", "token", "secret_key",
}
SECRET_INPUT_KEYS = REDACT_KEYS | {"credentials", "secrets", "api_token", "bearer_token"}
# Never let the caller smuggle a runner bootstrap through the terminal resource.
TERMINAL_FIELDS = {"terminal", "session_key"}


def operation(operation_id: str) -> dict:
    if operation_id not in OPERATIONS:
        raise ValueError("Unknown or excluded operation; use list_api_operations")
    return OPERATIONS[operation_id]


def _redact(value):
    if isinstance(value, dict):
        return {
            k: "[redacted]" if k.lower().replace("-", "_") in REDACT_KEYS else _redact(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(x) for x in value]
    return value


def _check_secret_fields(value):
    if isinstance(value, dict):
        for k, v in value.items():
            if k.lower().replace("-", "_") in SECRET_INPUT_KEYS and v not in (None, "", [], {}):
                raise ValueError("Secret credentials must be configured in Omnigent's native UI or CLI")
            _check_secret_fields(v)
    elif isinstance(value, list):
        for v in value:
            _check_secret_fields(v)


def _bound(value, max_bytes=MAX_RESULT):
    if len(json.dumps(value, ensure_ascii=False).encode()) > max_bytes:
        raise OmnigentError("Response exceeds MCP output limit; narrow or paginate the operation")
    return value


def path_for(op: dict, path_args: dict | None) -> str:
    args = path_args or {}
    expected = {m.group(1) for m in PATH_PARAMETER.finditer(op["path"])}
    if set(args) != expected:
        raise ValueError("Exact path arguments required: " + ", ".join(sorted(expected)))

    def replace(m):
        value = args[m.group(1)]
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise ValueError("Path arguments must be nonempty strings up to 4096 characters")
        if any(ord(c) < 32 or ord(c) == 127 for c in value) or any(c in value for c in ("%", "\\", "?", "#")):
            raise ValueError("Unsafe path argument")
        if any(part in (".", "..") for part in value.split("/")):
            raise ValueError("Path traversal segments are forbidden")
        if m.group(2):
            # Preserve internal separators in a FastAPI path converter, but
            # encode the leading slash as data, never as an alternate URL.
            if value.startswith("//"):
                raise ValueError("Invalid absolute path")
            return quote(value, safe="/" if not value.startswith("/") else "")
        if "/" in value:
            raise ValueError("An identifier cannot contain a slash")
        return quote(value, safe="")

    return PATH_PARAMETER.sub(replace, op["path"])


def openapi_path(op):
    return PATH_PARAMETER.sub(lambda m: "{" + m.group(1) + "}", op["path"])


def _local_ref(spec, ref):
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise ValueError("External OpenAPI references are not supported")
    value = spec
    for key in ref[2:].split("/"):
        value = value[key.replace("~1", "/").replace("~0", "~")]
    return value


def _check_local_refs(node):
    if isinstance(node, dict):
        if "$ref" in node and not str(node["$ref"]).startswith("#/"):
            raise ValueError("External OpenAPI references are not supported")
        # JSON Schema IDs can rebase relative references. Reject rebasing.
        if "$id" in node or "$dynamicRef" in node or "$recursiveRef" in node:
            raise ValueError("OpenAPI schema rebasing is not supported")
        for v in node.values():
            _check_local_refs(v)
    elif isinstance(node, list):
        for v in node:
            _check_local_refs(v)


def _resolved(spec, value):
    seen = set()
    while isinstance(value, dict) and "$ref" in value:
        ref = value["$ref"]
        if ref in seen:
            raise ValueError("Circular parameter reference")
        seen.add(ref)
        value = _local_ref(spec, ref)
    return value


def _schema_validate(spec, schema, value, label):
    if not schema:
        return
    _check_local_refs(schema)
    # Use only the in-memory live spec as the resolution root. No remote refs.
    resolver = RefResolver.from_schema(spec, handlers={
        "http": lambda _: (_ for _ in ()).throw(ValueError("Remote reference forbidden")),
        "https": lambda _: (_ for _ in ()).throw(ValueError("Remote reference forbidden")),
        "file": lambda _: (_ for _ in ()).throw(ValueError("File reference forbidden")),
    })
    try:
        Draft202012Validator(schema, resolver=resolver).validate(value)
    except ValidationError as exc:
        location = ".".join(str(x) for x in exc.absolute_path)
        # Do not echo request contents (they may contain confidential data).
        raise ValueError(f"{label} does not match upstream schema at {location or '(root)'}: {exc.validator}") from None


def _schema_fragment(spec, node):
    """Return only the locally referenced definitions, not the full spec."""
    definitions = {}
    seen = set()

    def walk(value):
        if isinstance(value, dict):
            if "$ref" in value:
                ref = value["$ref"]
                if ref not in seen:
                    seen.add(ref)
                    target = _local_ref(spec, ref)
                    definitions[ref] = target
                    walk(target)
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)

    walk(node)
    return definitions


def _parameter_list(spec, path_item, entry):
    params = {}
    for raw in path_item.get("parameters", []) + entry.get("parameters", []):
        p = _resolved(spec, raw)
        if p.get("in") in ("path", "query"):
            params[(p["in"], p["name"])] = p
    return list(params.values())


class BusinessAPI:
    def __init__(self, api: Omnigent):
        self.api = api
        self._lock = threading.Lock()
        self._spec = None
        self._spec_at = 0.0

    def spec(self, force=False):
        with self._lock:
            if not force and self._spec is not None and time.monotonic() - self._spec_at < 300:
                return self._spec
            response = self.api.request_data("GET", "/openapi.json", max_bytes=MAX_SPEC)
            if response["encoding"] != "json":
                raise OmnigentError("The upstream /openapi.json did not return JSON")
            spec = response["data"]
            if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict) or not str(spec.get("openapi", "")).startswith("3.1"):
                raise OmnigentError("A live OpenAPI 3.1 document is required")
            _check_local_refs(spec)
            self._spec, self._spec_at = spec, time.monotonic()
            return spec

    def entry(self, op):
        spec = self.spec()
        path_item = spec["paths"].get(openapi_path(op))
        if not isinstance(path_item, dict) or op["method"].lower() not in path_item:
            raise OmnigentError("Operation is not advertised by the running Omnigent server; it may be disabled or unsupported")
        entry = path_item[op["method"].lower()]
        return spec, path_item, entry

    def list_operations(self, domain=None, search=None, mode="all", offset=0, limit=50, live=False):
        if domain is not None and domain not in DOMAINS:
            raise ValueError("Unknown domain")
        if mode not in ("all", "read", "write") or not 1 <= limit <= 100 or offset < 0:
            raise ValueError("Invalid filter or pagination")
        spec = self.spec() if live else None
        result = []
        for op in OPERATIONS.values():
            if domain and op["domain"] != domain:
                continue
            if mode == "read" and op["method"] != "GET":
                continue
            if mode == "write" and op["method"] == "GET":
                continue
            if search and search.casefold() not in (op["id"]+" "+op["path"]+" "+op["domain"]).casefold():
                continue
            item = dict(op)
            if spec is not None:
                item["advertised"] = op["method"].lower() in spec["paths"].get(openapi_path(op), {})
            result.append(item)
        return {
            "upstream": CATALOG["upstream"], "domains": DOMAINS, "total": len(result),
            "operations": result[offset:offset+limit],
            "next_offset": offset+limit if offset+limit < len(result) else None,
            "availability": "live OpenAPI" if live else "source-derived; not live-verified",
        }

    def describe(self, operation_id):
        op = operation(operation_id)
        spec, path_item, entry = self.entry(op)
        params = _parameter_list(spec, path_item, entry)
        request_body = _resolved(spec, entry.get("requestBody", {}))
        result = {
            "operation": op,
            "summary": entry.get("summary", ""),
            "description": entry.get("description", ""),
            "path_args": [m.group(1) for m in PATH_PARAMETER.finditer(op["path"])],
            "parameters": params,
            "request_body": request_body,
            "referenced_schemas": _schema_fragment(spec, {"parameters": params, "requestBody": request_body}),
            "write_confirmation_required": op["method"] != "GET",
            "note": "Upstream validates final requests and permissions. Some manually parsed request fields are documented in the operation description instead of a JSON schema.",
        }
        override = MULTIPART_OVERRIDES.get(operation_id)
        if override:
            result["multipart_contract"] = {k: sorted(v) for k, v in override.items()}
            result["multipart_max_decoded_bytes"] = MAX_UPLOAD
        return _bound(result)

    def coverage(self, live=False):
        domains = {d: sum(op["domain"] == d for op in OPERATIONS.values()) for d in DOMAINS}
        result = {
            "upstream": CATALOG["upstream"],
            "catalog_operations": len(OPERATIONS), "domains": domains,
            "excluded": CATALOG["excluded"],
            "status": "source-derived candidates, not live functional verification",
        }
        if live:
            spec = self.spec(force=True)
            advertised = {(method.upper(), path) for path, item in spec["paths"].items() if path.startswith("/v1/") for method in item if method in ("get","post","put","patch","delete")}
            cataloged = {(op["method"],openapi_path(op)) for op in OPERATIONS.values()}
            matched = advertised & cataloged
            result.update({"live_http_operations": len(advertised), "catalog_matched": len(matched),
                "catalog_not_advertised": [{"method":m,"path":p} for m,p in sorted(cataloged-advertised)],
                "live_not_cataloged": [{"method":m,"path":p} for m,p in sorted(advertised-cataloged)],
                "status": "live OpenAPI inventory, not functional verification"})
        return _bound(result)

    def invoke(self, operation_id, mode, path_args=None, query=None, body=None, files=None, confirm=False):
        op = operation(operation_id)
        is_read = op["method"] == "GET"
        if (mode == "read") != is_read or mode not in ("read", "write"):
            raise PermissionError("Operation belongs to the other permission category")
        if not is_read and confirm is not True:
            raise PermissionError("Explicit user authorization is required for write operations")
        if is_read and (body is not None or files):
            raise ValueError("GET operations do not accept request bodies or files")
        path = path_for(op, path_args)
        spec, path_item, entry = self.entry(op)
        params = _parameter_list(spec, path_item, entry)
        query = query or {}
        if len(query) > 100 or any(not FIELD.fullmatch(k) for k in query):
            raise ValueError("Invalid query parameter names")
        _check_secret_fields(query)
        for p in params:
            source = query if p["in"] == "query" else (path_args or {})
            if p.get("required") and p["name"] not in source:
                # One legacy duplicate route exposes either environment listing
                # or path read; the upstream router resolves the actual query.
                if operation_id != "list_or_read_session_environments":
                    raise ValueError("Missing required parameter: "+p["name"])
            if p["name"] in source:
                _schema_validate(spec, p.get("schema"), source[p["name"]], p["name"])
        for val in query.values():
            if isinstance(val, (dict, list)) and (isinstance(val, dict) or any(isinstance(x,(dict,list)) for x in val)):
                raise ValueError("Query values must be scalars or arrays of scalars")
        if len(json.dumps(query).encode()) > 32_768:
            raise ValueError("Query too large")

        request_body = _resolved(spec, entry.get("requestBody", {}))
        content = request_body.get("content", {})
        if body is not None:
            _check_secret_fields(body)
            if len(json.dumps(body, ensure_ascii=False).encode()) > MAX_JSON:
                raise ValueError("Request body too large")
        if operation_id == "create_session_terminal":
            if not isinstance(body, dict) or not set(body).issubset(TERMINAL_FIELDS):
                raise ValueError("Only declared terminal and session_key may be supplied")
        if operation_id == "post_session_event":
            events = body if isinstance(body, list) else [body]
            if not 1 <= len(events) <= 100 or not all(isinstance(e, dict) for e in events):
                raise ValueError("Expected one or more client events")
            info = self.api.request_data("GET", "/v1/info", max_bytes=MAX_RESULT)["data"]
            allowed = info.get("session_event_types") if isinstance(info, dict) else None
            if not isinstance(allowed, list) or not all(isinstance(x, str) for x in allowed):
                raise OmnigentError("Server did not advertise its allowed client event types")
            for event in events:
                if event.get("type") not in allowed:
                    raise ValueError("Only advertised client events are accepted, not runner events")
                if event.get("type") == "message" and (not isinstance(event.get("data"), dict) or event["data"].get("role") != "user"):
                    raise ValueError("Messages must originate from the user")

        kwargs = {"params": query}
        if files:
            if not isinstance(files, list) or not 1 <= len(files) <= 21:
                raise ValueError("Expected 1–21 multipart files")
            override = MULTIPART_OVERRIDES.get(operation_id)
            if not override:
                raise ValueError("This operation has no reviewed multipart contract")
            if body is not None and not isinstance(body, dict):
                raise ValueError("Multipart form fields must be an object")
            fields = body or {}
            if not set(fields).issubset(override["fields"]):
                raise ValueError("Unknown multipart form fields")
            if operation_id == "create_session" and "metadata" not in fields:
                raise ValueError("Session upload requires metadata")
            if operation_id == "upload_session_github_attachment" and not isinstance(fields.get("pr_url"), str):
                raise ValueError("GitHub attachment requires pr_url")
            form = [(key, (None, json.dumps(val, ensure_ascii=False) if isinstance(val,(dict,list)) else str(val))) for key,val in fields.items()]
            seen = []
            total = 0
            for part in files:
                if not isinstance(part, dict) or set(part) - {"field","filename","content_base64","content_type"}:
                    raise ValueError("Invalid file part")
                field, filename, encoded = part.get("field"), part.get("filename"), part.get("content_base64")
                if field not in override["files"] or not isinstance(filename,str) or not filename or len(filename)>255 or any(c in filename for c in ("/","\\","\r","\n","\x00")):
                    raise ValueError("Invalid multipart field or filename")
                if field != "initial_files" and field in seen:
                    raise ValueError("Duplicate single-file part")
                if not isinstance(encoded,str) or len(encoded)>MAX_UPLOAD*2:
                    raise ValueError("Invalid or oversized base64 content")
                try:
                    raw = base64.b64decode(encoded, validate=True)
                except (ValueError,binascii.Error):
                    raise ValueError("Invalid base64 file content") from None
                total += len(raw)
                if total > MAX_UPLOAD:
                    raise ValueError("Total upload exceeds 2 MiB")
                media_type = part.get("content_type", "application/octet-stream")
                if not isinstance(media_type,str) or not re.fullmatch(r"[A-Za-z0-9.+_-]+/[A-Za-z0-9.+_-]+",media_type):
                    raise ValueError("Invalid content type")
                form.append((field,(filename,raw,media_type)))
                seen.append(field)
            if not override["required_files"].issubset(seen):
                raise ValueError("Missing required file part")
            kwargs["files"] = form
        else:
            if operation_id in ("install_agent","upload_session_file","upload_session_github_attachment"):
                raise ValueError("This operation requires multipart file upload")
            if request_body.get("required") and body is None:
                raise ValueError("Request body is required")
            if body is not None:
                if content and "application/json" not in content:
                    raise ValueError("This operation does not advertise a JSON request body")
                _schema_validate(spec,content.get("application/json",{}).get("schema"),body,"body")
                kwargs["body"] = body
        result = self.api.request_data(op["method"], path, max_bytes=MAX_RESULT, **kwargs)
        result["data"] = _redact(result["data"])
        return _bound({"operation_id":operation_id, **result})
