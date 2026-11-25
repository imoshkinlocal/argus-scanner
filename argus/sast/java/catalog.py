"""Catalogs of sources, sanitizers, propagators and sinks for the Java engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from ...models import Severity

# --------------------------------------------------------------------------- sources

#: Method names that introduce attacker controlled data.
SOURCE_METHODS: Dict[str, str] = {
    "getparameter": "request.getParameter",
    "getparametervalues": "request.getParameterValues",
    "getparametermap": "request.getParameterMap",
    "getparameternames": "request.getParameterNames",
    "getheader": "request.getHeader",
    "getheaders": "request.getHeaders",
    "getheadernames": "request.getHeaderNames",
    "getquerystring": "request.getQueryString",
    "getpathinfo": "request.getPathInfo",
    "getpathinfo2": "request.getPathInfo",
    "getinputstream": "request.getInputStream",
    "getreader": "request.getReader",
    "getcookies": "request.getCookies",
    "gettheparameter": "SeparateClassRequest.getTheParameter",
    "getthecookie": "SeparateClassRequest.getTheCookie",
    "getrequested": "request.getRequestedSessionId",
}

#: Servlet sources whose receiver must look like an HTTP request.  Without this
#: check ``ClassPathResource.getInputStream()`` (or any ``Foo.getReader()``) would
#: be mistaken for attacker controlled input.
SOURCE_RECEIVER_HINTS: Dict[str, Tuple[str, ...]] = {
    "getinputstream": ("request", "req", "servlet"),
    "getreader": ("request", "req", "servlet"),
    "getcookies": ("request", "req", "servlet"),
    "getquerystring": ("request", "req", "servlet"),
    "getpathinfo": ("request", "req", "servlet"),
    "getpathinfo2": ("request", "req", "servlet"),
    "getheaders": ("request", "req", "servlet", "header"),
    "getheadernames": ("request", "req", "servlet", "header"),
    "getrequested": ("request", "req", "servlet"),
}

#: ``Cookie.getValue()`` is only a source when the receiver is a cookie.
COOKIE_VALUE_SOURCE = "cookie.getValue"
COOKIE_TYPE_HINTS = ("cookie",)

#: Spring MVC parameter annotations that bind attacker controlled data.
#: An annotated controller parameter is tainted at method entry, which covers
#: ``@RequestBody`` objects whose fields are later read by getters as well.
SPRING_PARAM_ANNOTATIONS: Dict[str, str] = {
    "requestparam": "spring.@RequestParam",
    "pathvariable": "spring.@PathVariable",
    "requestbody": "spring.@RequestBody",
    "requestheader": "spring.@RequestHeader",
    "cookievalue": "spring.@CookieValue",
    "modelattribute": "spring.@ModelAttribute",
    "matrixvariable": "spring.@MatrixVariable",
    "requestpart": "spring.@RequestPart",
}

#: Numeric/boolean parameter types cannot carry an injection payload, so a
#: ``@RequestParam int id`` should not be treated as attacker controlled text.
SPRING_SAFE_PARAM_TYPES = frozenset({
    "int", "long", "short", "byte", "double", "float", "boolean", "char",
    "integer", "long", "short", "byte", "double", "float", "boolean",
    "character", "biginteger", "bigdecimal",
})

# --------------------------------------------------------------------------- sanitizers

ALL_CWES = frozenset({
    "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-501",
    "CWE-601", "CWE-611", "CWE-614", "CWE-643", "CWE-918",
})

_XSS = frozenset({"CWE-79"})
_SQL = frozenset({"CWE-89"})
_OS = frozenset({"CWE-78"})
_LDAP = frozenset({"CWE-90"})
_XPATH = frozenset({"CWE-643"})
_PATH = frozenset({"CWE-22"})

#: Encoders neutralise exactly one injection class, not "all taint".  A value
#: that was HTML-escaped is still dangerous when it is used as a file path or
#: as a session key, which is why the clean set is tracked per CWE.
SANITIZER_CWES: Dict[str, frozenset] = {
    "encodeforhtml": _XSS,
    "encodeforhtmlattribute": _XSS,
    "encodeforjavascript": _XSS,
    "encodeforjavascriptattribute": _XSS,
    "encodeforcss": _XSS,
    "encodeforurl": _XSS,
    "encodeforvbs": _XSS,
    "encodeforxml": _XSS,
    "encodeforxmlattribute": _XSS,
    "encodeforxmlcomment": _XSS,
    "encodeforhex": ALL_CWES,
    "escapehtml": _XSS,
    "escapehtml3": _XSS,
    "escapehtml4": _XSS,
    "escapejavascript": _XSS,
    "escapeecmascript": _XSS,
    "escapejava": _XSS,
    "escapejson": _XSS,
    "escapexml": _XSS,
    "escapexml10": _XSS,
    "escapexml11": _XSS,
    "htmlescape": _XSS,
    "encodeforsql": _SQL,
    "escapesql": _SQL,
    "tosqlidentifier": _SQL,
    "encodeforos": _OS,
    "encodeforldap": _LDAP,
    "encodefordn": _LDAP,
    "encodeforxpath": _XPATH,
    "encodeforbase64": ALL_CWES,
    "parseint": ALL_CWES,
    "parselong": ALL_CWES,
    "parsedouble": ALL_CWES,
    "parsefloat": ALL_CWES,
    "parseboolean": ALL_CWES,
    "parseshort": ALL_CWES,
    "parsebyte": ALL_CWES,
    "parseunsignedint": ALL_CWES,
    "parseunsignedlong": ALL_CWES,
}

SANITIZER_METHODS = frozenset(SANITIZER_CWES)

#: Methods returning a boolean (or a number) built from the input; the result
#: itself can never carry attacker data into a sink.
BOOLEAN_METHODS = frozenset(
    {
        "equals", "equalsignorecase", "contains", "containskey", "containsvalue",
        "startswith", "endswith", "isempty", "isblank", "matches", "hashcode",
        "compareto", "comparetoignorecase", "length", "size", "indexof",
        "lastindexof", "getname", "getpath", "exists", "canread", "canwrite",
        "hasnext", "hasmoreelements", "hasmoretokens", "nextint", "nextfloat",
        "nextdouble", "nextlong", "nextboolean", "next", "isdirectory", "isfile",
        "isinstance", "gettype", "ordinal", "name", "keys", "entryset",
    }
)

#: Methods whose result carries the taint of the receiver and/or arguments.
PROPAGATOR_METHODS = frozenset(
    {
        "trim", "strip", "substring", "subsequence", "tolowercase", "touppercase",
        "replace", "replaceall", "replacefirst", "concat", "format", "join",
        "tostring", "valueof", "getbytes", "getchars", "split", "decode", "encode",
        "canonicalize", "intern", "repeat", "indent", "lines", "chars",
        "codepoints", "tochararray", "copyof", "copyofrange", "aslist", "of",
        "append", "insert", "reverse", "delete", "deletecharat", "replacewith",
        "get", "getordefault", "getvalue", "getvalues", "getkey", "getname",
        "pull", "pop", "peek", "poll", "element", "first", "last", "remove",
        "iterator", "listiterator", "stream", "parallelstream", "toarray",
        "values", "keyset", "next", "nextline", "readline", "tostringbuilder",
        "mkstring", "getmessage", "getlocalizedmessage", "getcause",
        "getinputstream", "getoutputstream", "unchecked", "decodebase64",
        "nextelement", "nextelement2", "nexttoken", "pollfirst", "polllast",
        "getfirst", "getlast", "removefirst", "removelast", "aslist", "toarray",
        "encodebase64", "md5hex", "sha1hex", "digest", "dofinal", "update",
        "getinstance", "newinstance", "getresultlist", "getsingleresult",
        "getparameter", "getheader", "getproperty", "tobytes", "copy",
        "getresourceasstream", "getclassloader", "getresource",
        "dosomething",
    }
)

#: Collection/receiver mutators: taint the receiver variable itself.
MUTATOR_METHODS = frozenset(
    {
        "add", "addall", "put", "putall", "push", "offer", "set", "addfirst",
        "addlast", "append", "insert", "write", "writebytes", "writechars",
        "println", "print", "printf", "format", "replace", "replaceall",
        "delete", "deletecharat", "reverse", "sort", "addsuppressed",
    }
)


def normalize_algorithm(value: object) -> str:
    text = str(value or "").strip().strip("'\"").upper()
    return text.replace(" ", "")


_WEAK_CIPHER = ("DES", "DESEDE", "TRIPLEDES", "BLOWFISH", "RC2", "RC4", "ARCFOUR", "DESX", "SKIPJACK", "IDEA")
_WEAK_HASH = ("MD2", "MD4", "MD5", "SHA", "SHA1", "SHA-1", "RIPEMD128", "HAVAL128")


def is_weak_cipher(algorithm: object) -> bool:
    text = normalize_algorithm(algorithm)
    if not text:
        return False
    family = re.split(r"[/\-]", text, maxsplit=1)[0]
    return family in _WEAK_CIPHER


def is_weak_hash(algorithm: object) -> bool:
    text = normalize_algorithm(algorithm)
    if not text:
        return False
    if "/" in text:
        text = text.split("/", 1)[0]
    return text in _WEAK_HASH


# --------------------------------------------------------------------------- sinks

@dataclass(frozen=True)
class CallSink:
    """A taint sink expressed as a method call."""

    rule_id: str
    cwe: str
    severity: Severity
    title: str
    names: Tuple[str, ...]
    arg: Optional[int] = None          # None -> any argument, -1 -> receiver
    receiver_hints: Tuple[str, ...] = ()
    receiver_blocklist: Tuple[str, ...] = ()

    def matches(self, name: str, receiver_text: str) -> bool:
        if name not in self.names:
            return False
        receiver = receiver_text.lower()
        if self.receiver_blocklist and any(hint in receiver for hint in self.receiver_blocklist):
            return False
        if self.receiver_hints and not any(hint in receiver for hint in self.receiver_hints):
            return False
        return True


@dataclass(frozen=True)
class NewSink:
    """A taint sink expressed as an object instantiation."""

    rule_id: str
    cwe: str
    severity: Severity
    title: str
    types: Tuple[str, ...]
    arg: Optional[int] = None

    def matches(self, type_name: str) -> bool:
        return type_name.lower() in self.types


CALL_SINKS: Tuple[CallSink, ...] = (
    CallSink(
        "java-sqli-jdbc",
        "CWE-89",
        Severity.HIGH,
        "SQL injection: attacker controlled data in a JDBC statement",
        names=(
            "executequery", "executeupdate", "executelargeupdate", "addbatch",
            "preparestatement", "preparecall", "executebatch", "executelargebatch",
        ),
    ),
    CallSink(
        "java-sqli-statement-execute",
        "CWE-89",
        Severity.HIGH,
        "SQL injection: attacker controlled data executed as SQL",
        names=("execute",),
        receiver_hints=("stmt", "statement", "jdbc", "dbconnection", "connection"),
    ),
    CallSink(
        "java-sqli-template",
        "CWE-89",
        Severity.HIGH,
        "SQL injection: attacker controlled data passed to a template query",
        names=(
            "batchupdate", "queryforobject", "queryforlist", "queryformap",
            "queryforlong", "queryforint", "queryforrowset", "query", "update",
        ),
        receiver_hints=("template", "jdbc", "repository", "dao"),
    ),
    CallSink(
        "java-sqli-jpa",
        "CWE-89",
        Severity.HIGH,
        "SQL injection: attacker controlled JPQL/native query",
        names=("createquery", "createnativequery", "createsqlquery"),
    ),
    CallSink(
        "java-xss-writer",
        "CWE-79",
        Severity.HIGH,
        "Cross-site scripting: attacker controlled data written to the response",
        names=("print", "println", "printl", "printfln", "write", "format", "printf", "append", "writebytes", "writechars"),
        receiver_hints=("response", "getwriter", "getoutputstream", "writer", " out", "out."),
        receiver_blocklist=("file", "system.err", "system.out", "logger", "log."),
    ),
    CallSink(
        "java-cmdi-runtime",
        "CWE-78",
        Severity.HIGH,
        "OS command injection: attacker controlled data reaches Runtime.exec",
        names=("exec",),
        receiver_hints=("runtime", "getruntime"),
    ),
    CallSink(
        "java-cmdi-processbuilder",
        "CWE-78",
        Severity.HIGH,
        "OS command injection: attacker controlled data used to build a process",
        names=("command", "exec"),
        receiver_hints=("processbuilder", "pb", "process"),
    ),
    CallSink(
        "java-pathtraver-javaio",
        "CWE-22",
        Severity.HIGH,
        "Path traversal: attacker controlled path used to open a file",
        names=(
            "get", "of", "newinputstream", "newoutputstream", "readallbytes",
            "readalllines", "readstring", "write", "writestring", "copy", "move",
            "newbufferedreader", "newbufferedwriter", "delete", "deleteifexists",
            "createdirectories", "createdirectory",
        ),
        receiver_hints=("paths", "path", "files"),
    ),
    CallSink(
        "java-ldapi",
        "CWE-90",
        Severity.HIGH,
        "LDAP injection: attacker controlled data in an LDAP query",
        names=("search", "lookup", "bind", "rebind", "createsubcontext", "destroysubcontext", "listbindings"),
        receiver_hints=("ctx", "context", "ldap", "dircontext"),
    ),
    CallSink(
        "java-xpathi",
        "CWE-643",
        Severity.HIGH,
        "XPath injection: attacker controlled data in an XPath expression",
        names=("compile", "evaluate", "compileexpression"),
        receiver_hints=("xpath", "expression", "eval"),
    ),
    CallSink(
        "java-xxe",
        "CWE-611",
        Severity.HIGH,
        "XML external entity: attacker controlled XML input parsed without hardening",
        names=("parse", "parseinputsource", "unmarshal", "transform", "build", "newsaxparser"),
        receiver_hints=(
            "builder", "parser", "reader", "unmarshaller", "transformer",
            "saxbuilder", "documentbuilder", "xmlinput", "dbf",
        ),
    ),
    CallSink(
        "java-trustbound",
        "CWE-501",
        Severity.HIGH,
        "Trust boundary violation: attacker controlled key stored in the session",
        names=("setattribute",),
    ),
    CallSink(
        "java-trustbound-value",
        "CWE-501",
        Severity.HIGH,
        "Trust boundary violation: attacker controlled value stored in the session",
        names=("putvalue",),
    ),
    CallSink(
        "java-ssrf",
        "CWE-918",
        Severity.MEDIUM,
        "Server-side request forgery: attacker controlled URL",
        names=("openconnection", "openstream", "getforobject", "exchange", "retrieve"),
        receiver_hints=("url", "resttemplate", "httpclient", "webclient", "connection"),
    ),
    CallSink(
        "java-open-redirect",
        "CWE-601",
        Severity.MEDIUM,
        "Open redirect: attacker controlled redirect target",
        names=("sendredirect",),
    ),
)


NEW_SINKS: Tuple[NewSink, ...] = (
    NewSink(
        "java-pathtraver-file",
        "CWE-22",
        Severity.HIGH,
        "Path traversal: attacker controlled path used to build a File object",
        types=("file", "fileinputstream", "fileoutputstream", "filereader",
               "filewriter", "randomaccessfile", "filechannel", "printwriter",
               "printstream", "zipfile", "jarfile"),
        arg=None,
    ),
    NewSink(
        "java-cmdi-processbuilder-new",
        "CWE-78",
        Severity.HIGH,
        "OS command injection: attacker controlled command in ProcessBuilder",
        types=("processbuilder",),
    ),
    NewSink(
        "java-ssrf-url",
        "CWE-918",
        Severity.MEDIUM,
        "Server-side request forgery: attacker controlled URL",
        types=("url", "uri"),
        arg=0,
    ),
)

#: Cookie flags that weaken transport security.
COOKIE_FLAG_RULES = (
    ("setsecure", "java-securecookie", "CWE-614", Severity.MEDIUM,
     "Cookie created without the Secure flag"),
    ("sethttponly", "java-httponly", "CWE-1004", Severity.MEDIUM,
     "Cookie created without the HttpOnly flag"),
)

LIST_TYPES = frozenset({
    "arraylist", "linkedlist", "vector", "copyonwritearraylist", "stack",
    "hashset", "linkedhashset", "treeset", "arraydeque", "priorityqueue",
    "concurrentlinkedqueue", "concurrentlinkeddeque", "list", "collection",
})

MAP_TYPES = frozenset({
    "hashmap", "linkedhashmap", "treemap", "hashtable", "concurrenthashmap",
    "weakashmap", "weakhashmap", "identityhashmap", "properties", "map",
})

WEAK_RANDOM_TYPES = ("random",)
WEAK_RANDOM_METHODS = ("random",)

CRYPTO_GETINSTANCE_RECEIVERS = {
    "cipher": ("java-weak-cipher", "CWE-327", Severity.HIGH,
               "Weak cryptographic cipher"),
    "keygenerator": ("java-weak-cipher", "CWE-327", Severity.HIGH,
                     "Weak cryptographic key algorithm"),
    "secretkeyfactory": ("java-weak-cipher", "CWE-327", Severity.HIGH,
                         "Weak cryptographic key algorithm"),
    "keyfactory": ("java-weak-cipher", "CWE-327", Severity.HIGH,
                   "Weak cryptographic key algorithm"),
    "messagedigest": ("java-weak-hash", "CWE-328", Severity.MEDIUM,
                      "Weak hash algorithm"),
    "mac": ("java-weak-hash", "CWE-328", Severity.MEDIUM, "Weak MAC algorithm"),
    "signature": ("java-weak-hash", "CWE-328", Severity.MEDIUM, "Weak signature algorithm"),
}

SECRET_NAME_RE = re.compile(
    r"(?i)(^|_)(password|passwd|pass|secret|token|apikey|api_key|access_key|"
    r"secret_key|private_key|auth_key|credentials?)($|_)"
)
SECRET_PLACEHOLDERS = ("", "changeme", "change-me", "xxx", "***", "todo", "none", "null", "password")


def rule_catalog() -> List[dict]:
    """Human/JSON readable catalogue of every rule the Java engine can report."""
    seen: Dict[str, dict] = {}
    for sink in CALL_SINKS:
        seen.setdefault(sink.rule_id, {
            "rule_id": sink.rule_id, "cwe": sink.cwe, "severity": sink.severity.value,
            "title": sink.title, "kind": "call",
        })
    for sink in NEW_SINKS:
        seen.setdefault(sink.rule_id, {
            "rule_id": sink.rule_id, "cwe": sink.cwe, "severity": sink.severity.value,
            "title": sink.title, "kind": "constructor",
        })
    for _method, rule_id, cwe, severity, title in COOKIE_FLAG_RULES:
        seen.setdefault(rule_id, {
            "rule_id": rule_id, "cwe": cwe, "severity": severity.value,
            "title": title, "kind": "cookie-flag",
        })
    structural = [
        ("java-weak-cipher", "CWE-327", Severity.HIGH,
         "Weak cryptographic algorithm requested from a JCA factory"),
        ("java-weak-hash", "CWE-328", Severity.MEDIUM, "Broken hash algorithm requested"),
        ("java-weak-random", "CWE-330", Severity.MEDIUM, "Predictable pseudo-random generator"),
        ("java-open-redirect", "CWE-601", Severity.MEDIUM,
         "Attacker controlled redirect target"),
        ("java-hardcoded-secret", "CWE-798", Severity.HIGH, "Hardcoded credential"),
    ]
    for rule_id, cwe, severity, title in structural:
        seen.setdefault(rule_id, {
            "rule_id": rule_id, "cwe": cwe, "severity": severity.value,
            "title": title, "kind": "pattern",
        })
    return sorted(seen.values(), key=lambda item: (item["cwe"], item["rule_id"]))
