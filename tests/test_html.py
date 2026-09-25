from email_forensics.html_analysis import analyze_html, is_hidden_style


def test_visible_and_hidden_text():
    html, visible = analyze_html(
        '<p>Hello <b>there</b></p><div style="display:none">secret words</div>'
        '<span style="font-size:0px">tiny</span><span hidden>attr</span>'
        "<script>var x=1</script><style>p{}</style>",
        "1",
    )
    assert "Hello there" in visible
    assert "secret" not in visible and "var x" not in visible
    assert html.hidden_text == ["secret words", "tiny", "attr"]
    assert html.scripts == 1


def test_hidden_style_detection():
    assert is_hidden_style("display: none")
    assert is_hidden_style("color:#fff;background-color:#fff")
    assert is_hidden_style("font-size:0")
    assert is_hidden_style("opacity:0;")
    assert not is_hidden_style("font-size:10px")
    assert not is_hidden_style("line-height:0;color:red")
    assert not is_hidden_style("opacity:0.5")
    assert not is_hidden_style("font-size: ;opacity:;")
    assert is_hidden_style("font-size:0.0em")


def test_links_and_anchor_text():
    html, _ = analyze_html(
        '<a href="https://evil.test/x">https://bank.com</a>'
        '<img src="https://t.test/p.gif" width="1" height="1">'
        '<img src="https://cdn.test/logo.png" width="200" height="50">'
        '<iframe src="https://frame.test"></iframe>'
        '<meta http-equiv="refresh" content="0; url=https://redir.test/">'
        '<td background="https://bg.test/b.jpg"></td>'
        '<div style="background:url(\'https://css.test/a.png\')"></div>',
        "1",
    )
    by_source = {(l.source, l.url) for l in html.links}
    assert ("a", "https://evil.test/x") in by_source
    assert ("iframe", "https://frame.test") in by_source
    assert ("meta-refresh", "https://redir.test/") in by_source
    assert ("img", "https://bg.test/b.jpg") in by_source
    assert ("css", "https://css.test/a.png") in by_source
    anchor = next(l for l in html.links if l.source == "a")
    assert anchor.text == "https://bank.com"
    assert html.tracking_pixels == ["https://t.test/p.gif"]
    assert html.meta_refresh == "https://redir.test/"


def test_forms_and_event_handlers():
    html, _ = analyze_html(
        '<form action="https://x.test/c"><input type="text"><input type="password"></form>'
        '<body onload="go()">',
        "1",
    )
    assert html.forms[0].action == "https://x.test/c"
    assert html.forms[0].input_types == ["text", "password"]
    assert html.event_handlers == ["body.onload"]


def test_unclosed_and_garbage_html_does_not_raise():
    html, visible = analyze_html("<div style='display:none'><a href='x'>< <<<>>> &bogus; </p></td>", "1")
    assert html.part == "1"
