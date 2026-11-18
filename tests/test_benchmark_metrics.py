from src.benchmark import detection_metrics, quality_metrics


def test_metrics_include_known_misses_and_false_positives():
    a=("file",1,"rule");b=("file",2,"rule");c=("file",3,"rule")
    result=detection_metrics({a:"ruleid",b:"todoruleid",c:"ok"},{a,c})
    assert result["precision"]==0.5
    assert result["recall"]==0.5
    assert result["known_limit_misses"]==1


def test_unknown_quality_is_not_reported_as_success():
    metrics=quality_metrics([{"explanation_correct":None,"fix_usable":False}])
    assert metrics["explanation_accuracy"]["rate"] is None
    assert metrics["usable_fix_rate"]["rate"]==0
