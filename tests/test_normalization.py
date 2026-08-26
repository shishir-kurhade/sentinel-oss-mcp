from sentinel_oss.normalization import normalize_text


def test_normalization_removes_invisible_separators_and_collapses_whitespace() -> None:
    assert normalize_text("  h\u200barmful\u00a0\u00a0text  ") == "harmful text"


def test_normalization_uses_nfkc() -> None:
    assert normalize_text("ＦＵＬＬＷＩＤＴＨ") == "FULLWIDTH"
