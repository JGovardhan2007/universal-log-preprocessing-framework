import pytest
from core_engine.ai_analyzer import AIAnalyzer


def test_shannon_entropy_calculation():
    # Low entropy (uniform string)
    low_ent = AIAnalyzer.calculate_shannon_entropy("AAAAAAAAAA")
    assert low_ent == 0.0

    # Normal English / standard syslog text (typically 2.5 - 3.8)
    normal_text = "Accepted password for root from 192.168.1.50 port 22 ssh2"
    norm_ent = AIAnalyzer.calculate_shannon_entropy(normal_text)
    assert 2.5 <= norm_ent <= 4.2

    # High entropy (base64 encoded shellcode / random bytes)
    b64_payload = "W1teX11eWV1eXFteWF5cW15YXlxbXlheXFteWF5cW15YXlxbWExMjM0NTY3ODk="
    high_ent = AIAnalyzer.calculate_shannon_entropy(b64_payload)
    assert high_ent >= 4.0


def test_ai_analyzer_singleton_and_models():
    analyzer = AIAnalyzer.get_instance()
    assert analyzer is not None
    assert analyzer._is_trained is True

    status = analyzer.get_ensemble_status()
    assert status["ensemble_mode"] == "Weighted Multi-Model Consensus"
    assert "iforest" in status["models"]
    assert "ocsvm" in status["models"]
    assert "entropy" in status["models"]
    assert "temporal" in status["models"]
    assert status["models"]["iforest"]["status"] == "OPERATIONAL"


def test_ai_analyzer_inference_benign():
    analyzer = AIAnalyzer.get_instance()
    benign_log = "May 24 10:15:30 authpriv.notice sshd[1234]: Accepted publickey for devuser from 10.0.0.15 port 52341 ssh2"
    rec = {
        "src_endpoint": {"port": 52341},
        "dst_endpoint": {"port": 22},
        "connection_info": {"protocol_name": "TCP"},
        "actor": {"user": {"name": "devuser"}}
    }

    res = analyzer.analyze_log(benign_log, rec)
    assert "composite_score" in res
    assert "entropy" in res
    assert "iforest_score" in res
    assert "ocsvm_score" in res
    assert "jitter_score" in res
    assert "xai_tags" in res
    # Benign log should have low composite threat score (< 0.70)
    assert res["composite_score"] < 0.70


def test_ai_analyzer_inference_high_entropy_exfiltration():
    analyzer = AIAnalyzer.get_instance()
    # Malicious DNS C2 payload with high entropy subdomain
    malicious_log = "DNS QUERY type=A name=q8J9kL2mNxP5rT7vW0yB3cE6gH1jK4mP7sU9wX2zA5dF8hJ1.attacker-c2.net src=192.168.1.100:53535 dst=8.8.8.8:53"
    rec = {
        "src_endpoint": {"port": 53535},
        "dst_endpoint": {"port": 53},
        "connection_info": {"protocol_name": "UDP"},
        "actor": {"user": {"name": "unknown"}}
    }

    res = analyzer.analyze_log(malicious_log, rec)
    assert res["entropy"] >= 4.0
    assert any("Entropy" in tag for tag in res["xai_tags"])
