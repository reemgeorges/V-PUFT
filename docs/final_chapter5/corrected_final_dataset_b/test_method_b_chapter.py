from validate_method_b_chapter import verify

def test_dataset_b_chapter_semantics():
    report = verify()
    assert report["failed"] == 0
    assert report["passed"] >= 50
    assert report["primary_case_differences"] == 2
