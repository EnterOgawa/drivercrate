"""用途限定locator取得plan／evidenceを小さな架空台帳で非通信検証する。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
実製品・HTTP・installerは使わず、拒否境界と旧URL契約を確認する。
"""
from copy import deepcopy
import unittest
import collector_locator_acquisition as a
import collector_literal_downloads as literal
import collector_public_locators as pl
import collector_registry as cr
from test_collector_literal_downloads import fixture, PAGE, ACTION, URL


def inputs():
    """明示fake観測を持つ一製品・一配布・三locatorの自作fixtureを返す。"""
    stamp, root = '2026-10-07T00:00:00Z', 'https://example.org/en/'
    registry = cr.validate_registry(dict(schema=cr.REGISTRY_SCHEMA, revision='synthetic-locator-fixture', asOf=stamp,
        sources=[dict(id='source1', manufacturer='Synthetic', officialPage=root, collectionMethod='MANUAL_RESEARCH')],
        products=[dict(id='product1', manufacturer='Synthetic', model='Synthetic Adapter', driverCategory='SERIAL',
            sourceIds=['source1'], recordIds=['record1'], researchState='METADATA_SAVED', reason='NONE')],
        records=[dict(id='record1', sourceId='source1', title='Synthetic Archive', driverCategory='SERIAL',
            operatingSystems=['WINDOWS_11_X64'], packageVersion=None, driverVersion=None, publishedDate=None,
            downloadUrl=None, linkState='MISSING', publishedSha256=None, contentState='NOT_DOWNLOADED')],
        observations=[dict(id='root-observation', productId='product1', recordId=None, checkedAt=stamp,
            kind='OFFICIAL_PAGE', method='LOCAL_HTTP', evidenceUrl=root, httpStatus=200, evidenceSha256='a' * 64),
            dict(id='record-review', productId='product1', recordId='record1', checkedAt=stamp,
            kind='OFFICIAL_PAGE', method='WEB_REVIEW', evidenceUrl=root, httpStatus=None, evidenceSha256=None)]))
    observation = dict(method='LOCAL_HTTP', httpStatus=200, bodyBytes=512, bodySha256='a' * 64, checkedAt=stamp)
    locators = pl.validate_locators(dict(schema=pl.LOCATOR_SCHEMA, revision='synthetic-locator-pages', asOf=stamp,
        registry=pl.registry_binding(registry), researchOnly=True, publishable=False, installAuthorized=False,
        locators=[dict(id='root-page', sourceId='source1', purpose='PAGE', url=root, urlProfile='QUERYLESS',
            productIds=['product1'], recordIds=[], parentPageIds=[], requestCondition='PUBLIC_METADATA',
            publicationCondition='REVIEW_REQUIRED', pageObservation=observation),
            dict(id='child-page', sourceId='source1', purpose='PAGE', url=PAGE, urlProfile='PUBLIC_PRODUCT_PID',
            productIds=['product1'], recordIds=['record1'], parentPageIds=['root-page'], requestCondition='PUBLIC_METADATA',
            publicationCondition='REVIEW_REQUIRED', pageObservation=observation),
            dict(id='payload1', sourceId='source1', purpose='PAYLOAD', url=URL, urlProfile='PUBLIC_DOWNLOAD_FILE_PATH',
            productIds=['product1'], recordIds=['record1'], parentPageIds=['child-page'], requestCondition='ACCESS_UNRESOLVED',
            publicationCondition='REVIEW_REQUIRED', pageObservation=None)]), registry)
    proof = dict(schema='dc-literal-download-derivations-v1', researchOnly=True, publishable=False,
        installAuthorized=False, nativeConnected=False, method=literal.METHOD, payloadRequests=0, postRequests=0,
        entries=[dict(recordId='record1', url=URL, urlProfile='PUBLIC_DOWNLOAD_FILE_PATH', productIds=['product1'],
        operatingSystems=['WINDOWS_11_X64'], requestAuthorized=False, httpObserved=False, payloadDownloaded=False,
        preNavigationPostExecuted=False, evidence=[dict(productId='product1', page=PAGE,
            reviewMethod='MANUAL_FUNCTION_REVIEW', originalBodyReparsed=False, automaticInlineBlockParseMatched=False,
            bodySha256='a' * 64, observedAt=stamp, receiptSha256='b' * 64, action=ACTION,
            transfer=literal.recognize_transfer(fixture()))])])
    plan = dict(schema=a.PLAN_SCHEMA, revision='synthetic-locator-acquisition', registrySha256=cr.digest(cr.json_bytes(registry)),
        locatorsSha256=cr.digest(cr.json_bytes(locators)), derivationsSha256=cr.digest(cr.json_bytes(proof)),
        maximumTotalBytes=32 * 1024**2, maximumRequests=2, items=[dict(recordId='record1', locatorId='payload1',
        format='ZIP', maximumBytes=8 * 1024**2, preDownloadConsent='NO_GATE_OBSERVED_IN_PAGE_FUNCTION')])
    return [registry, locators, proof, plan]


class LocatorAcquisitionTests(unittest.TestCase):
    """根拠・用途・予算と取得／署名／内容の独立状態を検証する。"""

    def reject(self, change, rebind=False):
        """各caseの新規fixtureへchangeを同期適用し、RegistryErrorを要求する。

        rebind=Trueでは変更後のregistry／locator／derivationのhashをplanへ戻し、
        古い外側hashの拒否だけで内側の不正を見逃さないようにする。
        """
        values = inputs()
        change(values)
        if rebind:
            for name, index in (('registrySha256', 0), ('locatorsSha256', 1), ('derivationsSha256', 2)):
                values[3][name] = cr.digest(cr.json_bytes(values[index]))
        with self.assertRaises(cr.RegistryError):
            a.validate_plan(*values)

    def evidence(self):
        values = inputs()
        row = dict(id='synthetic-acquisition', recordId='record1', checkedAt=values[0]['asOf'], state='DOWNLOADED',
            httpStatus=200, bytes=1024, sha256='c' * 64, outerSignature='NOT_CHECKED', publisher=None,
            inspection='UNSUPPORTED', inspectorSha256=None, inspectionExitCode=None, verifiedInfs=0,
            rejectedInfs=0, inventoryFiles=0, reason='NONE')
        return values, dict(schema=a.EVIDENCE_SCHEMA, planSha256=a.validate_plan(*values)['planSha256'],
            registrySha256=values[3]['registrySha256'], asOf=values[0]['asOf'], acquisitions=[row])

    def test_valid_plan(self):
        self.assertEqual(a.validate_plan(*inputs())['payloadUrls'][0]['url'], URL)

    def test_stale_plan(self):
        self.reject(lambda values: values[3].update(registrySha256='d' * 64))

    def test_unknown_fields(self):
        self.reject(lambda values: values[3].update(allowPost=True))

    def test_more_requests(self):
        self.reject(lambda values: values[3].update(maximumRequests=3))

    def test_total_budget(self):
        self.reject(lambda values: values[3].update(maximumTotalBytes=1))

    def test_duplicate_record(self):
        self.reject(lambda values: values[3]['items'].append(deepcopy(values[3]['items'][0])))

    def test_consent_unknown(self):
        self.reject(lambda values: values[3]['items'][0].update(preDownloadConsent='ACCEPTED'))

    def test_wrong_purpose(self):
        self.reject(lambda values: values[3]['items'][0].update(locatorId='child-page'))

    def test_wrong_format(self):
        self.reject(lambda values: values[3]['items'][0].update(format='EXE'))

    def test_missing_action(self):
        self.reject(lambda values: values[2]['entries'][0]['evidence'][0].update(action=ACTION + ';alert(1)'), True)

    def test_scope_swap(self):
        self.reject(lambda values: values[2]['entries'][0].update(operatingSystems=['WINDOWS_10_X64']), True)

    def test_page_hash_swap(self):
        self.reject(lambda values: values[2]['entries'][0]['evidence'][0].update(bodySha256='e' * 64), True)

    def test_post_authority(self):
        self.reject(lambda values: values[2].update(postRequests=1), True)

    def test_grant_promotion(self):
        self.reject(lambda values: values[2]['entries'][0].update(requestAuthorized=True), True)

    def test_valid_evidence(self):
        values, evidence = self.evidence()
        self.assertEqual(a.validate_evidence(*values, evidence), evidence)

    def test_download_without_bytes(self):
        values, evidence = self.evidence()
        evidence['acquisitions'][0]['bytes'] = 0
        with self.assertRaises(cr.RegistryError):
            a.validate_evidence(*values, evidence)

    def test_passed_without_inf(self):
        values, evidence = self.evidence()
        evidence['acquisitions'][0].update(inspection='PASSED', inspectorSha256='f' * 64, inspectionExitCode=0)
        with self.assertRaises(cr.RegistryError):
            a.validate_evidence(*values, evidence)

    def test_signature_without_publisher(self):
        values, evidence = self.evidence()
        evidence['acquisitions'][0]['outerSignature'] = 'VALID'
        with self.assertRaises(cr.RegistryError):
            a.validate_evidence(*values, evidence)

    def test_failure_with_content(self):
        values, evidence = self.evidence()
        evidence['acquisitions'][0].update(state='FAILED', reason='TRANSFER_FAILED')
        with self.assertRaises(cr.RegistryError):
            a.validate_evidence(*values, evidence)

    def test_legacy_url_predicate_unchanged(self):
        with self.assertRaises(cr.RegistryError):
            cr.public_url(URL, purpose='PAYLOAD')


if __name__ == '__main__':
    unittest.main()
