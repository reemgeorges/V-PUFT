from vpuft.sumo.doctor import doctor_report


def test_doctor_always_returns_structured_report():
    report = doctor_report()
    assert isinstance(report.ready_for_sumo, bool)
    assert isinstance(report.notes, tuple)
