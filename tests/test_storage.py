from sentinel_local.storage.repository import get_saved_analysis, init_analysis_table, list_saved_analyses, save_analysis


def test_save_and_load_analysis_round_trip(tmp_path) -> None:
    database_path = tmp_path / "sentinel.db"
    init_analysis_table(database_path)

    saved = save_analysis(
        database_path=database_path,
        subject="Test subject",
        sender="alerts@example.com",
        source_type="eml",
        verdict="suspicious",
        score=35,
        confidence="medium",
        analyst_note="SOC escalation",
        parsed_email={"subject": "Test subject"},
        extraction_result={"indicators": []},
        header_analysis_result={"mail_flow": [], "originating_ips": [], "reply_to": [], "findings": []},
        analysis_result={
            "score": 35,
            "verdict": "suspicious",
            "disposition": "phishing",
            "confidence": "medium",
            "rule_hits": [],
        },
        analyst_summary_result={
            "summary": "test summary",
            "likely_intent": "test intent",
            "recommended_actions": ["do the thing"],
            "evidence_highlights": ["rule hit"],
        },
        url_analysis_result={"artifacts": [], "html_artifacts": []},
        attachment_analysis_result={"artifacts": []},
        attachment_scan_result={"artifacts": [], "warnings": []},
        enrichment_result={"records": []},
        narrative_report={"summary": "test", "verdict_rationale": "because", "recommended_actions": []},
        markdown_report="# report",
    )

    loaded = get_saved_analysis(database_path, saved.analysis_id)
    recent = list_saved_analyses(database_path)

    assert loaded is not None
    assert loaded.analysis_id == saved.analysis_id
    assert loaded.subject == "Test subject"
    assert loaded.analyst_summary_result is not None
    assert recent[0].analysis_id == saved.analysis_id
