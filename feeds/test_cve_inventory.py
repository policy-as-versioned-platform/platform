import importlib.util
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('converter', Path(__file__).with_name('to_fair_scenario.py'))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
FEED = {'feed_version': 'kev', 'severity_lm_gbp': {'CRITICAL': [100,200,300]}, 'cves': {'CVE-2021-44228': {'component':'Apache Log4j','cvss':10,'severity':'CRITICAL','epss':0.9,'source':'CISA/NVD/FIRST'}}}
def inventory(ids):
    return {'schema_version':'1.0.0','images':[{'image':'example@sha256:'+'a'*64,'digest':'sha256:'+'a'*64,'scanner_version':'0.69.3','database_date':'2026-09-25T00:00:00Z','vulnerabilities':[{'id': i, 'package':'log4j','installed_version':'2.14.1','fixed_version':'2.17.1','severity':'CRITICAL'} for i in ids]}]}
def test_intersection_and_named_absence():
    got = m.cve_scenario(FEED, inventory=inventory(['CVE-2021-44228','CVE-2099-0001']))
    assert got['priced_cve'] == 'CVE-2021-44228'
    assert got['absences'] == [{'id':'CVE-2099-0001','amount':None,'reason':'outside pinned KEV feed'}]
    absent = m.cve_scenario(FEED, inventory=inventory(['CVE-2099-0001']))
    assert absent['priced_cve'] is None and absent['amount'] is None
    assert absent['absence_count'] == 1
    with pytest.raises(SystemExit, match='missing instrument'):
        m.cve_scenario(FEED)
