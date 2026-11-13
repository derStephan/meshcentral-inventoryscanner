#!/usr/bin/env bash
#
# Functional integration test for the inventoryscanner plugin, executed INSIDE the current
# meshcentral/meshcentral Docker container (CI administration only - see the workflow that
# pipes this file in). It touches no plugin code and publishes nothing.
#
# The server runs with ARGS=--nousers: every loopback request gets a site-admin session of
# the default domain (the dummy user is exactly the account class the plugin's
# isAuthorizedAdmin gate expects). curl, jq and bash ship with the MeshCentral image.
#
# env input:  PLUGIN_VER - the version from the plugin's config.json (must show in the panel)
#
# Deliberately NEVER called here: update_nvd (would start downloading hundreds of MB of NVD
# feeds - CI seeds a 0-CVE feed file instead), wg_run and os_run (they would open command
# sessions against agents that do not exist in this job). Those engines are covered by the
# mocked behavioral suite tools/test-plugin.js, which the same workflow runs natively.

set -u
BASE=https://127.0.0.1
P="$BASE/pluginadmin.ashx?pin=inventoryscanner"
DATA=/opt/meshcentral/meshcentral-data
HDRC='X-InvScanner-Request: 1'
BODY=/tmp/inv-ci-body
PASS=0
FAILS=0
FAILED_NAMES=''

ok()  { PASS=$((PASS+1)); echo "PASS  $1"; }
bad() { FAILS=$((FAILS+1)); FAILED_NAMES="$FAILED_NAMES
 - $1"; echo "FAIL  $1"; }

get_auth()   { curl -ks --max-time 30 -H "Cookie: xid=$XID" -o "$BODY" -w '%{http_code}' "$P$1"; }
get_anon()   { curl -ks --max-time 30 -o "$BODY" -w '%{http_code}' "$P$1"; }
post_auth()  { curl -ks --max-time 30 -H "Cookie: xid=$XID" -H "$HDRC" -o "$BODY" -w '%{http_code}' -X POST "$P" "$@"; }
post_nohdr() { curl -ks --max-time 30 -H "Cookie: xid=$XID" -o "$BODY" -w '%{http_code}' -X POST "$P" "$@"; }
post_anon()  { curl -ks --max-time 30 -H "$HDRC" -o "$BODY" -w '%{http_code}' -X POST "$P" "$@"; }

chk()    { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got HTTP $3, want $2)"; fi; }
chkjq()  { if jq -e "$2" "$BODY" >/dev/null 2>&1; then ok "$1"; else bad "$1 [jq: $2] body: $(head -c 220 "$BODY" | tr '\n' ' ')"; fi; }
chkfile(){ if [ -e "$2" ]; then ok "$1"; else bad "$1 (missing: $2)"; fi; }

echo "== session and auth gates =="
HDRS=$(curl -ks -D - -o /dev/null "$BASE/")
XID=$(printf '%s' "$HDRS" | sed -n 's/.*xid=\([^;]*\).*/\1/p' | head -n1 | tr -d '\r')
if [ -n "$XID" ]; then ok 'GET / establishes an admin session cookie'; else bad 'no xid session cookie from GET /'; printf '%s\n' "$HDRS" | head -n 20; fi

chk 'panel GET without a session is refused'           401 "$(get_anon '&action=show')"
chk 'panel POST without a session is refused'          401 "$(post_anon --data 'action=get_locations')"
chk 'panel GET with the session renders'               200 "$(get_auth '&action=show')"
if grep -q "plugin v${PLUGIN_VER:-unknown}" "$BODY"; then ok 'the panel shows the running plugin version'; else bad "panel does not show plugin v${PLUGIN_VER:-unknown}"; fi
if grep -q 'inventoryscanner' "$BODY"; then ok 'the panel references the plugin shortName'; else bad 'panel missing the shortName'; fi
chk 'POST without the cross-site header is refused'    403 "$(post_nohdr --data 'action=get_locations')"
chk 'POST with an unknown action 404s'                 404 "$(post_auth --data 'action=does_not_exist')"
chk 'GET with an unknown action 404s'                  404 "$(get_auth '&action=nope')"

echo
echo "== GET routes: scan, reports, CSV export =="
chk 'scan with no mesh parameter'                      200 "$(get_auth '&action=scan')"
chkjq 'scan response shape' '(.cves|type=="array") and (.meshes|type=="array")'
chk 'scan with a location that does not exist'         200 "$(get_auth '&action=scan&mesh=mesh//CI-Location')"
chk 'vulnerability report renders'                     200 "$(get_auth '&action=report')"
if grep -qi 'Vulnerability Report' "$BODY"; then ok 'report view content'; else bad 'report view content'; fi
chk 'device report renders'                            200 "$(get_auth '&action=deviceReport')"
if grep -qi 'Device Inventory Report' "$BODY"; then ok 'deviceReport view content'; else bad 'deviceReport view content'; fi
for t in vulns hardware software; do
    chk "CSV export type=$t"                            200 "$(get_auth "&action=export&type=$t")"
    if head -c 3 "$BODY" | od -An -tx1 | grep -qi 'ef bb bf'; then ok "CSV export type=$t carries the UTF-8 BOM"; else bad "CSV export type=$t BOM missing"; fi
done
chk 'CSV export with an invalid type is refused'       400 "$(get_auth '&action=export&type=bogus')"
chk 'legacy show_cpe'                                 200 "$(get_auth '&action=show_cpe')"
chkjq 'show_cpe shape' '.entries|type=="array"'

echo
echo "== settings: defaults -> overlay -> revert -> validation =="
chk 'get_settings'                                    200 "$(post_auth --data 'action=get_settings')"
chkjq 'built-in defaults are in effect' '.settings.scanIntervalHours==24 and .settings.updateHours==168 and .sources.scanIntervalHours=="default"'
SAVEFORM='action=save_settings&scanIntervalHours=12&updateHours=168&anyCveMaxAgeYears=5&collectIntervalMinutes=60&notifyThreshold=HIGH&notifyOnScan=true&notifyUnratedRepeat=false&autoProductMatch=true&cpeTableEnabled=true&distroManaged=true&osLifecycleEnabled=true&collectOnAgentConnect=true&scanMeshes=&notifyMeshIds=&notifySeverities=&cpeTableUrl=&osLifecycleUrl='
chk 'save_settings accepts the full form'             200 "$(post_auth --data "$SAVEFORM")"
chkjq 'the saved override wins' '.settings.scanIntervalHours==12 and .sources.scanIntervalHours=="file"'
chkfile 'the overlay file was written' "$DATA/plugins/inventoryscanner/scanner-settings.json"
chk 'save_settings rejects updateHours=0'             200 "$(post_auth --data "${SAVEFORM/updateHours=168/updateHours=0}")"
chkjq '...as an error, not a crash' 'has("error")'
chk 'save_settings rejects an invalid threshold'      200 "$(post_auth --data "${SAVEFORM/notifyThreshold=HIGH/notifyThreshold=NOPE}")"
chkjq '...as an error' 'has("error")'
chk 'revert_setting'                                  200 "$(post_auth --data 'action=revert_setting&revertScanIntervalHours=true')"
chk 'get_settings after the revert'                   200 "$(post_auth --data 'action=get_settings')"
chkjq 'the default applies again' '.settings.scanIntervalHours==24 and .sources.scanIntervalHours=="default"'
chk 'reset=true clears the scanner sections'          200 "$(post_auth --data 'action=save_settings&reset=true')"
chkjq '...successfully' '.success==true'

echo
echo "== CPE mapping table: curated load + custom CRUD + validation =="
chk 'get_cpe_table'                                   200 "$(post_auth --data 'action=get_cpe_table')"
chkjq 'the curated table is live' '.cpeTable.source=="remote" and (.entries|type=="array")'
chk 'add_cpe'                                         200 "$(post_auth --data 'action=add_cpe' --data-urlencode 'match=^CI Test Software$' --data 'vendor=civendor' --data 'product=ciproduct')"
chkjq '...stored as a custom entry' '.success==true and ([.entries[]|select(.match=="^CI Test Software$")]|length)==1'
chk 'the custom entry shows in the table'             200 "$(post_auth --data 'action=get_cpe_table')"
chkjq '...marked custom' '[.entries[]|select(.source=="custom" and .match=="^CI Test Software$")]|length==1'
chk 'add_cpe rejects an unsafe regex'                 200 "$(post_auth --data 'action=add_cpe' --data-urlencode 'match=(a+)+' --data 'vendor=x' --data 'product=y')"
chkjq '...with an error' 'has("error")'
LONGVENDOR=$(head -c 201 /dev/zero | tr '\0' 'a')
chk 'add_cpe rejects an over-long vendor'             200 "$(post_auth --data 'action=add_cpe' --data 'match=^CI other$' --data-urlencode "vendor=$LONGVENDOR" --data 'product=y')"
chkjq '...with an error' 'has("error")'
chk 'delete_cpe_table removes the custom entry'       200 "$(post_auth --data 'action=delete_cpe_table' --data-urlencode 'match=^CI Test Software$' --data 'vendor=civendor' --data 'product=ciproduct')"
chkjq '...successfully' '.success==true'
chk 'the table after the delete'                      200 "$(post_auth --data 'action=get_cpe_table')"
chkjq '...without the custom entry' '[.entries[]|select(.match=="^CI Test Software$")]|length==0'

echo
echo "== assessments: validation + multi-location write + false positives =="
chk 'rating without a comment is refused'             200 "$(post_auth --data 'action=save_assessment' --data 'meshIds=mesh//CI-A,mesh//CI-B' --data 'cveId=CVE-2099-44228' --data 'assessment=HIGH')"
chkjq '...with an error' 'has("error")'
chk 'rating with a malformed CVE id is refused'       200 "$(post_auth --data 'action=save_assessment' --data 'meshIds=mesh//CI-A' --data 'cveId=NOT-A-CVE' --data 'assessment=HIGH' --data 'comment=ci')"
chkjq '...with an error' 'has("error")'
chk 'rating with a malformed mesh id is refused'      200 "$(post_auth --data 'action=save_assessment' --data 'meshIds=mesh//bad:id' --data 'cveId=CVE-2099-44228' --data 'assessment=HIGH' --data 'comment=ci')"
chkjq '...with an error' 'has("error")'
chk 'rating over two locations in one request'        200 "$(post_auth --data 'action=save_assessment' --data 'meshIds=mesh//CI-A,mesh//CI-B' --data 'cveId=CVE-2099-44228' --data 'assessment=HIGH' --data-urlencode 'comment=accepted risk for CI')"
chkjq '...success' '.success==true'
chkfile 'assessments persisted' "$DATA/nvd/assessments.json"
chk 'scan still answers with the rating stored'       200 "$(get_auth '&action=scan&mesh=mesh//CI-A,mesh//CI-B')"
chk 'flag_false_positive'                             200 "$(post_auth --data 'action=flag_false_positive' --data 'meshId=mesh//CI-A' --data 'cveId=CVE-2099-44228')"
chkjq '...flagged' '.success==true and .flagged==true'
chk 'unflag_false_positive'                           200 "$(post_auth --data 'action=unflag_false_positive' --data 'meshId=mesh//CI-A' --data 'cveId=CVE-2099-44228')"
chkjq '...unflagged' '.success==true and .flagged==false'
chk 'flagging a malformed finding id is refused'      200 "$(post_auth --data 'action=flag_false_positive' --data 'meshId=mesh//CI-A' --data 'cveId=EVT-1')"
chkjq '...with an error' 'has("error")'

echo
echo "== winget + OS update engines (device-less surface) =="
chk 'wg_get_config'                                   200 "$(post_auth --data 'action=wg_get_config')"
chkjq 'winget is off by default' '.config.enabled==false and .sources.enabled=="default"'
chk 'wg_save_config'                                  200 "$(post_auth --data 'action=wg_save_config' --data 'enabled=false' --data 'updateMeshes=' --data 'excludeNodes=' --data 'ignorePackages=[]' --data 'pinSync=true')"
chkjq '...stored in the overlay' '.sources.enabled=="file"'
chk 'wg_status'                                       200 "$(post_auth --data 'action=wg_status')"
chkjq '...no windows devices, nothing queued' '(.devices|type=="array") and ((.devices|length)==0) and (.queued==0)'
chk 'wg_programs'                                     200 "$(post_auth --data 'action=wg_programs')"
chkjq '...no package results yet' '(.packages|type=="array") and ((.packages|length)==0)'
chk 'os_status'                                       200 "$(post_auth --data 'action=os_status')"
chkjq '...full surface, no devices' '(.devices|type=="array") and (.current|type=="object") and ((.devices|length)==0)'

echo
echo "== software deploy engine (library + tasks, device-less) =="
chk 'sw_files'                                        200 "$(post_auth --data 'action=sw_files')"
chkjq '...empty library with the real limits' '(.files|type=="array") and ((.files|length)==0) and (.limits.chunkBytes==49152) and (.limits.exts|index("msi") != null)'
chk 'sw_rescan_library'                               200 "$(post_auth --data 'action=sw_rescan_library')"
chkjq '...answers the counts' 'has("added") and has("removed") and (.files|type=="array")'
chk 'sw_serverfiles'                                  200 "$(post_auth --data 'action=sw_serverfiles')"
chkjq '...folders listed' '(.folders|type=="array")'
chk 'sw_devices'                                      200 "$(post_auth --data 'action=sw_devices')"
chkjq '...no devices yet' '(.devices|type=="array") and ((.devices|length)==0)'
chk 'sw_status'                                       200 "$(post_auth --data 'action=sw_status')"
chkjq '...no tasks' '(.tasks|type=="array") and ((.tasks|length)==0) and has("queued")'
chk 'sw_create_task validates the file id'            200 "$(post_auth --data 'action=sw_create_task' --data 'source=library' --data 'fileId=zzzz' --data 'nodeIds=node//x')"
chkjq '...rejected' 'has("error")'
chk 'sw_upload validates the upload id'               200 "$(post_auth --data 'action=sw_upload' --data 'uploadId=zz' --data 'name=a.msi' --data 'index=0' --data 'data=AAAA')"
chkjq '...rejected' 'has("error")'
chk 'sw_retry_task rejects a malformed task id'       200 "$(post_auth --data 'action=sw_retry_task' --data 'taskId=zz')"
chkjq '...with an error' 'has("error")'
chk 'sw_cancel_task rejects a malformed task id'      200 "$(post_auth --data 'action=sw_cancel_task' --data 'taskId=zz')"
chkjq '...with an error' 'has("error")'
chk 'sw_delete_file rejects a malformed file id'      200 "$(post_auth --data 'action=sw_delete_file' --data 'fileId=zz')"
chkjq '...with an error' 'has("error")'

echo
echo "== logs =="
for t in nvd winget os deploy; do
    chk "get_log type=$t"                             200 "$(post_auth --data 'action=get_log' --data-urlencode "type=$t")"
    chkjq "...tails a lines array" 'has("lines")'
done
chk 'get_log rejects an unknown type'                 200 "$(post_auth --data 'action=get_log' --data 'type=bogus')"
chkjq '...with an error' 'has("error")'
chk 'get_nvdlog'                                      200 "$(post_auth --data 'action=get_nvdlog')"
chkjq '...answers' 'has("lines")'
chk 'get_locations'                                   200 "$(post_auth --data 'action=get_locations')"
chkjq '...all locations listed' '(.locations|type=="array") and ((.locations|length)==0)'

echo
echo '=================================================='
echo "inventoryscanner vs live MeshCentral: $PASS passed, $FAILS failed"
if [ "$FAILS" -gt 0 ]; then printf 'failed checks:%s\n' "$FAILED_NAMES"; exit 1; fi
