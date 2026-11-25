"""Tests for the Java tree-sitter taint engine."""

from __future__ import annotations

from argus.sast.java import analyze_file
from argus.sast.java.engine import JavaEngine


def findings_for(path: str):
    return JavaEngine(path, open(path, "rb").read()).run()


def rules(path: str):
    return {finding.rule_id for finding in findings_for(path)}


def test_sql_injection_detected(java_source):
    path = java_source("""
        String p = request.getParameter("id");
        java.sql.Statement st = null;
        st.executeQuery("SELECT * FROM users WHERE id = '" + p + "'");
    """)
    assert "java-sqli-jdbc" in rules(path)


def test_parse_int_sanitises_sql(java_source):
    path = java_source("""
        String p = request.getParameter("id");
        int id = Integer.parseInt(p);
        java.sql.Statement st = null;
        st.executeQuery("SELECT * FROM users WHERE id = " + id);
    """)
    assert "java-sqli-jdbc" not in rules(path)


def test_dead_branch_is_folded(java_source):
    path = java_source("""
        String p = request.getParameter("id");
        int num = 106;
        String bar = (7 * 18) + num > 200 ? "safe" : p;
        response.getWriter().println(bar);
    """)
    assert "java-xss-writer" not in rules(path)


def test_live_branch_is_reported(java_source):
    path = java_source("""
        String p = request.getParameter("id");
        int num = 0;
        String bar = (7 * 18) + num > 200 ? "safe" : p;
        response.getWriter().println(bar);
    """)
    assert "java-xss-writer" in rules(path)


def test_list_add_remove_get_flow(java_source):
    path = java_source("""
        String p = request.getParameter("id");
        java.util.List<String> values = new java.util.ArrayList<String>();
        values.add("safe");
        values.add(p);
        values.add("moresafe");
        values.remove(0);
        String bar = values.get(0);
        response.getWriter().println(bar);
    """)
    assert "java-xss-writer" in rules(path)


def test_map_put_get_flow(java_source):
    path = java_source("""
        String p = request.getParameter("id");
        java.util.Map<String, String> map = new java.util.HashMap<String, String>();
        map.put("key", p);
        String bar = map.get("key");
        response.getWriter().println(bar);
    """)
    assert "java-xss-writer" in rules(path)


def test_switch_char_at_is_folded(java_source):
    path = java_source("""
        String p = request.getParameter("id");
        String guess = "ABC";
        char target = guess.charAt(2);
        String bar;
        switch (target) {
            case 'A': bar = p; break;
            case 'B': bar = "bobs_your_uncle"; break;
            case 'C':
            case 'D': bar = p; break;
            default: bar = "bobs_your_uncle"; break;
        }
        response.getWriter().println(bar);
    """)
    assert "java-xss-writer" in rules(path)


def test_string_builder_flow(java_source):
    path = java_source("""
        String p = request.getParameter("id");
        StringBuilder sb = new StringBuilder(p);
        String bar = sb.append("_SafeStuff").toString();
        response.getWriter().println(bar);
    """)
    assert "java-xss-writer" in rules(path)


def test_output_encoder_survives_concatenation(java_source):
    path = java_source("""
        String p = request.getParameter("id");
        String bar = ESAPI.encoder().encodeForHTML(p);
        response.getWriter().println("hello '" + bar + "'");
    """)
    assert "java-xss-writer" not in rules(path)


def test_encoder_does_not_clean_other_cwes(java_source):
    path = java_source("""
        String p = request.getParameter("id");
        String bar = ESAPI.encoder().encodeForHTML(p);
        java.sql.Statement st = null;
        st.executeQuery("SELECT * FROM t WHERE a = '" + bar + "'");
    """)
    assert "java-sqli-jdbc" in rules(path)


def test_file_writer_is_not_an_xss_sink(java_source):
    path = java_source("""
        String p = request.getParameter("id");
        java.io.FileWriter writer = new java.io.FileWriter("out.txt");
        writer.write(p);
    """)
    assert "java-xss-writer" not in rules(path)


def test_help_method_identity_propagates(java_source):
    path = java_source("""
        String p = request.getParameter("id");
        String bar = identity(p);
        response.getWriter().println(bar);
    """)
    # ``identity`` is not declared: the engine must stay silent instead of
    # inventing a flow, but a same-file helper is resolved (see next test).
    assert "java-xss-writer" not in rules(path)


def test_same_file_helper_flow(java_source):
    path = java_source("""
        String p = request.getParameter("id");
        String bar = wrapper(p);
        response.getWriter().println(bar);
        }
        private String wrapper(String value) {
            return value;
    """)
    assert "java-xss-writer" in rules(path)


def test_weak_crypto_hash_random(java_source):
    path = java_source("""
        javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");
        java.security.MessageDigest.getInstance("MD5");
        java.util.Random random = new java.util.Random();
    """)
    found = rules(path)
    assert {"java-weak-cipher", "java-weak-hash", "java-weak-random"} <= found


def test_strong_crypto_is_clean(java_source):
    path = java_source("""
        javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        java.security.MessageDigest.getInstance("SHA-256");
        java.security.SecureRandom random = new java.security.SecureRandom();
    """)
    assert not {"java-weak-cipher", "java-weak-hash", "java-weak-random"} & rules(path)


def test_cookie_flags(java_source):
    path = java_source("""
        Cookie cookie = new Cookie("name", "value");
        cookie.setSecure(false);
        cookie.setHttpOnly(false);
    """)
    found = rules(path)
    assert "java-securecookie" in found
    assert "java-httponly" in found


def test_trust_boundary_checks_both_arguments(java_source):
    path = java_source("""
        String p = request.getParameter("id");
        request.getSession().putValue("key", p);
        request.getSession().setAttribute(p, "value");
    """)
    found = rules(path)
    assert "java-trustbound-value" in found
    assert "java-trustbound" in found


def test_command_injection_through_list(java_source):
    path = java_source("""
        String p = request.getParameter("cmd");
        java.util.List<String> args = new java.util.ArrayList<String>();
        args.add("sh");
        args.add("-c");
        args.add("echo " + p);
        ProcessBuilder builder = new ProcessBuilder();
        builder.command(args);
        builder.start();
    """)
    assert "java-cmdi-processbuilder" in rules(path)


def test_non_request_get_input_stream_is_not_a_source(java_source):
    path = java_source("""
        org.springframework.core.io.ClassPathResource resource =
                new org.springframework.core.io.ClassPathResource("domains.xml");
        javax.xml.parsers.DocumentBuilderFactory factory =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(resource.getInputStream());
    """)
    assert "java-xxe" not in rules(path)


def test_request_input_stream_is_a_source(java_source):
    path = java_source("""
        javax.xml.parsers.DocumentBuilderFactory factory =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(request.getInputStream());
    """)
    assert "java-xxe" in rules(path)


def test_analyze_file_uses_relative_paths(tmp_path, java_source):
    path = java_source("""
        String p = request.getParameter("id");
        response.getWriter().println(p);
    """)
    findings = analyze_file(path, str(tmp_path))
    assert findings
    assert findings[0].file == "Sample.java"
    assert findings[0].start_line > 0
    assert findings[0].kind == "sast"
    assert findings[0].engine == "argus-java"


def test_clean_servlet_has_no_findings(java_source):
    path = java_source("""
        response.setContentType("text/plain");
        response.getWriter().println("static text");
    """)
    assert findings_for(path) == []


# --------------------------------------------------------------------------- Spring MVC

SPRING_CONTROLLER = """\
package demo;

import org.springframework.web.bind.annotation.*;
import java.sql.Statement;

@RestController
public class Controller {

    @GetMapping("/search")
    public String search(@RequestParam("id") String id) throws Exception {
        Statement st = null;
        st.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
        return "ok";
    }

    @PostMapping("/run")
    public String run(@RequestBody Command command) throws Exception {
        Runtime.getRuntime().exec("echo " + command.getName());
        return "ok";
    }

    @GetMapping("/file")
    public String file(@RequestHeader("X-Path") String path) throws Exception {
        return new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path)));
    }

    @GetMapping("/safe")
    public String safe(@RequestParam int id) throws Exception {
        Statement st = null;
        st.executeQuery("SELECT * FROM users WHERE id = " + id);
        return "ok";
    }
}
"""


def _spring_findings(tmp_path):
    path = tmp_path / "Controller.java"
    path.write_text(SPRING_CONTROLLER)
    return JavaEngine(str(path), path.read_bytes()).run()


def test_spring_request_param_is_a_sql_source(tmp_path, capsys):
    findings = _spring_findings(tmp_path)
    sqli = [finding for finding in findings if finding.rule_id == "java-sqli-jdbc"]
    assert sqli, "annotated controller parameter must reach the SQL sink"
    assert "spring.@RequestParam" in sqli[0].message


def test_spring_request_body_is_a_command_source(tmp_path):
    findings = _spring_findings(tmp_path)
    cmdi = [finding for finding in findings if finding.rule_id == "java-cmdi-runtime"]
    assert cmdi
    assert "spring.@RequestBody" in cmdi[0].message


def test_spring_request_header_reaches_path_sink(tmp_path):
    findings = _spring_findings(tmp_path)
    assert any("spring.@RequestHeader" in finding.message for finding in findings)


def test_spring_numeric_param_is_not_tainted(tmp_path):
    findings = _spring_findings(tmp_path)
    sqli = [finding for finding in findings if finding.rule_id == "java-sqli-jdbc"]
    assert len(sqli) == 1, "only the String @RequestParam should be reported"
