from scripts.funnel_report import summarize


def test_summarize_groups_events_sources_and_unique_tabs():
    lines = [
        '2026-07-14T09:00:00+00:00 "POST /events?e=page_view&sid=a&source=reddit&campaign=launch HTTP/2.0" 204 "-"',
        '2026-07-14T09:00:01+00:00 "POST /events?e=page_view&sid=a&source=reddit&campaign=launch HTTP/2.0" 204 "-"',
        '2026-07-14T09:00:02+00:00 "POST /events?e=checkout_click&sid=a&source=reddit&campaign=launch HTTP/2.0" 204 "-"',
        '2026-07-14T09:00:03+00:00 "POST /events?e=smoke_test&sid=test&source=codex HTTP/2.0" 204 "-"',
    ]

    report = summarize(lines)

    assert report["events"] == {"page_view": 2, "checkout_click": 1}
    assert report["unique_sessions_by_event"] == {"checkout_click": 1, "page_view": 1}
    assert report["sources"] == {"reddit": 3}
    assert report["campaigns"] == {"launch": 3}
