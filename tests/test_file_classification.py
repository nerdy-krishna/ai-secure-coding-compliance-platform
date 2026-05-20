from app.shared.lib.file_classification import (
    CATEGORY_FIRST_PARTY_MINIFIED_BUNDLE,
    CATEGORY_FIRST_PARTY_SOURCE,
    CATEGORY_KNOWN_THIRD_PARTY_VENDOR,
    classify_file,
)


def test_known_vendor_jquery_detected():
    result = classify_file(
        "static/vendor/jquery.min.js",
        "/*! jQuery JavaScript Library v3.7.1 */\n" + "var a=1;" * 200,
    )
    assert result["classification"] == CATEGORY_KNOWN_THIRD_PARTY_VENDOR
    assert result["known_library"]["name"] == "jquery"
    assert result["coverage_policy"]["dependency_intel"] is True


def test_app_owned_minified_bundle_without_signature():
    result = classify_file("assets/app.min.js", "function a(){return 1};" * 200)
    assert result["classification"] == CATEGORY_FIRST_PARTY_MINIFIED_BUNDLE
    assert "missing_source_map_reduced_client_coverage" in result["coverage_warnings"]


def test_source_map_detection_marks_submitted_map():
    result = classify_file(
        "dist/app.min.js",
        "function a(){}\n//# sourceMappingURL=app.min.js.map",
        submitted_paths={"dist/app.min.js", "dist/app.min.js.map"},
    )
    assert result["source_map"] == {"url": "app.min.js.map", "submitted": True}


def test_first_party_source_normal_policy():
    result = classify_file("src/app.py", "print('hello')\n")
    assert result["classification"] == CATEGORY_FIRST_PARTY_SOURCE
    assert result["coverage_policy"]["llm_analysis"] is True
    assert result["coverage_policy"]["semgrep"] is True
