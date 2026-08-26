tb_host = '''
SELECT *
FROM tb_host
WHERE host_id=:param
    AND is_deleted=0
'''

tb_host_by_uuid = '''
SELECT *
FROM tb_host
WHERE host_uuid=:param
    AND is_deleted=0
'''

tb_scan = '''
SELECT *
FROM tb_scan
WHERE host_id=:param
    AND is_deleted=0
ORDER BY collected_at DESC
LIMIT 1
'''

tb_scan_recent = '''
SELECT scan_id, host_id, collected_at, package_count, exposure_count
FROM tb_scan
WHERE host_id=:param
    AND is_deleted=0
ORDER BY collected_at DESC
LIMIT 2
'''

tb_finding = '''
SELECT * 
FROM tb_finding
WHERE scan_id=:param
    AND is_deleted=0
'''

tb_finding_evidence = '''
SELECT *
FROM tb_finding_evidence
WHERE finding_id IN :param
'''

tb_cve = '''
SELECT *
FROM tb_cve
WHERE cve_id IN :param
    AND is_deleted=0
'''

tb_kev_catalog = '''
SELECT *
FROM tb_kev_catalog
WHERE cve_id IN :param
'''

tb_exposure = '''
SELECT *
FROM tb_exposure
WHERE scan_id=:param
'''

tb_process = '''
SELECT *
FROM tb_process
WHERE scan_id=:param
'''

tb_package = '''
SELECT *
FROM tb_package
WHERE scan_id=:param
'''

tb_container = '''
SELECT *
FROM tb_container
WHERE scan_id=:param
'''

tb_collection_stage = '''
SELECT *
FROM tb_collection_stage
WHERE scan_id=:param
'''

tb_package_dependency = '''
SELECT *
FROM tb_package_dependency
WHERE scan_id=:param
'''

tb_cce_finding = '''
SELECT *
FROM tb_cce_finding
WHERE scan_id=:param
'''

tb_pkg_change = '''
SELECT *
FROM tb_pkg_change
WHERE scan_id=:param
    AND is_deleted=0
'''

tb_stale_lib = '''
SELECT *
FROM tb_stale_lib
WHERE scan_id=:param
    AND is_deleted=0
'''