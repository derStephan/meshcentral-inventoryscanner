#!/usr/bin/env bash
#
# Functional integration test for the inventoryscanner plugin, executed INSIDE the current
# meshcentral/meshcentral Docker container (CI administration only - see the workflow that
# pipes this file in). It touches no plugin code and publishes nothing.
#
# The server runs a REAL admin account: the workflow provisions 'ciadmin' with MeshCentral's own
# one-shot CLIs (--createaccount + --adminaccount) and starts the server with ARGS="--user ciadmin",
# which auto-establishes the site-admin session on the first root request - exactly the account
# class (siteadmin 0xFFFFFFFF, default domain) the plugin's isAuthorizedAdmin gate demands.
# curl, jq, bash and meshctrl.js ship with the MeshCentral image.
# One live LINUX mesh agent (the server's own meshagents?id=6 binary, driven by the server's own
# meshsettings?id=... install material) is attached to a 'CI-Group' device group - the agent
# sections below prove the collector, the inventory CSV/reports and the whole software-deploy
# pipeline (wget + agentdownload cookie + SHA-256 + runcommands) against a genuine agent.
#
# env input:  PLUGIN_VER - the version from the plugin's config.json (must show in the panel)
#
# Deliberately NEVER called here: update_nvd (would start downloading hundreds of MB of NVD
# feeds - CI seeds a 0-CVE feed file instead), wg_run / os_run (Windows/OS batches against the
# one agent make no sense; the winget engine is covered by the mocked suite tools/test-plugin.js).

set -u
BASE=https://127.0.0.1
P="$BASE/pluginadmin.ashx?pin=inventoryscanner"
DATA=/opt/meshcentral/meshcentral-data
HDRC='X-InvScanner-Request: 1'
BODY=/tmp/inv-ci-body
CKV=''
PASS=0
FAILS=0
FAILED_NAMES=''

ok()  { PASS=$((PASS+1)); echo "PASS  $1"; }
bad() { FAILS=$((FAILS+1)); FAILED_NAMES="$FAILED_NAMES
 - $1"; echo "FAIL  $1"; }

get_auth()   { curl -ks --max-time 30 -H "Cookie: $CKV" -o "$BODY" -w '%{http_code}' "$P$1"; }
get_anon()   { curl -ks --max-time 30 -o "$BODY" -w '%{http_code}' "$P$1"; }
post_auth()  { curl -ks --max-time 30 -H "Cookie: $CKV" -H "$HDRC" -o "$BODY" -w '%{http_code}' -X POST "$P" "$@"; }
post_nohdr() { curl -ks --max-time 30 -H "Cookie: $CKV" -o "$BODY" -w '%{http_code}' -X POST "$P" "$@"; }
post_anon()  { curl -ks --max-time 30 -H "$HDRC" -o "$BODY" -w '%{http_code}' -X POST "$P" "$@"; }

chk()    { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got HTTP $3, want $2)"; fi; }
chkjq()  { if jq -e "$2" "$BODY" >/dev/null 2>&1; then ok "$1"; else bad "$1 [jq: $2] body: $(head -c 220 "$BODY" | tr '\n' ' ')"; fi; }
chkfile(){ if [ -e "$2" ]; then ok "$1"; else bad "$1 (missing: $2)"; fi; }

echo "== session and auth gates =="
HDRS=$(curl -ks -D - -o /dev/null "$BASE/")
XID=$(printf '%s' "$HDRS"  | sed -n 's/.*[Cc]ookie: xid=\([^;]*\).*/\1/p'      | head -n1 | tr -d '\r')
XSIG=$(printf '%s' "$HDRS" | sed -n 's/.*[Cc]ookie: xid\.sig=\([^;]*\).*/\1/p' | head -n1 | tr -d '\r')
if [ -n "$XID" ]; then ok 'GET / establishes an admin session cookie'; else bad 'no xid session cookie from GET /'; printf '%s\n' "$HDRS" | head -n 20; fi
CKV="xid=$XID"
if [ -n "$XSIG" ]; then CKV="$CKV; xid.sig=$XSIG"; fi

chk 'panel GET without a session is refused'           401 "$(get_anon '&action=show')"
chk 'panel POST without a session is refused'          401 "$(post_anon --data 'action=get_locations')"
chk 'panel GET with the session renders'               200 "$(get_auth '&action=show')"
if grep -q "plugin v${PLUGIN_VER:-unknown}" "$BODY"; then ok 'the panel shows the running plugin version'; else bad "panel does not show plugin v${PLUGIN_VER:-unknown}"; fi
if grep -q 'inventoryscanner' "$BODY"; then ok 'the panel references the plugin shortName'; else bad 'panel missing the shortName'; fi
chk 'POST without the cross-site header is refused'    403 "$(post_nohdr --data 'action=get_locations')"
chk 'POST with an unknown action 404s'                 404 "$(post_auth --data 'action=does_not_exist')"
chk 'GET with an unknown action 404s'                  404 "$(get_auth '&action=nope')"
# v4.3.2: the name link on My Server -> Plugins (goPlugin) opens ?pin=inventoryscanner WITHOUT action
chk 'GET without action (plugin list link) renders'    200 "$(get_auth '')"
if grep -q "plugin v${PLUGIN_VER:-unknown}" "$BODY"; then ok '...and it is the panel'; else bad 'GET without action did not render the panel'; fi
# v4.3.2: the one-click upgrade restarts the server only when it runs as the --launch child of
# MeshCentral's launcher (which relaunches it on "Server restart..."). Prove the image does that.
if cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\0' ' ' | grep -q -- '[-]-launch'; then ok 'server runs under the MeshCentral launcher (--launch child, upgrade restart possible)'; else bad 'no --launch child process: an upgrade would fall back to the hot swap'; fi

echo
echo "== GET routes: scan, reports, CSV export =="
chk 'scan with no mesh parameter'                      200 "$(get_auth '&action=scan')"
chkjq '...answers the contract error' 'has("error")'
chk 'scan with a location that does not exist'         200 "$(get_auth '&action=scan&mesh=mesh//CI-Location')"
chkjq 'scan response shape' '(.cves|type=="array") and (.meshes|type=="array") and has("flaggedCount") and has("totalCves")'
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
chkjq '...device shape (a not-yet-registered osdesc keeps the row by design)' '(.devices|type=="array") and (.queued==0)'
chk 'wg_programs'                                     200 "$(post_auth --data 'action=wg_programs')"
chkjq '...no package results yet' '(.packages|type=="array") and ((.packages|length)==0)'
chk 'os_status'                                       200 "$(post_auth --data 'action=os_status')"
chkjq '...full surface' '(.devices|type=="array") and (.current|type=="object")'

echo
echo "== software deploy engine (library + tasks, device-less) =="
chk 'sw_files'                                        200 "$(post_auth --data 'action=sw_files')"
chkjq '...empty library with the real limits' '(.files|type=="array") and ((.files|length)==0) and (.limits.chunkBytes==49152) and (.limits.exts|index("msi") != null)'
chk 'sw_rescan_library'                               200 "$(post_auth --data 'action=sw_rescan_library')"
chkjq '...answers the counts' 'has("added") and has("removed") and (.files|type=="array")'
chk 'sw_serverfiles'                                  200 "$(post_auth --data 'action=sw_serverfiles')"
chkjq '...folders listed' '(.folders|type=="array")'
chk 'sw_devices'                                      200 "$(post_auth --data 'action=sw_devices')"
chkjq '...device list is an array' '(.devices|type=="array")'
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
chkjq '...the CI device group is listed' '[.locations[]|select(.name=="CI-Group")]|length==1'
GROUPID=$(jq -r '[.locations[]|select(.name=="CI-Group")][0].id // empty' "$BODY")
if [ -n "$GROUPID" ]; then ok "group id captured ($GROUPID)"; else bad 'group id missing'; fi

echo
echo "== live linux agent: online, collected, deployed =="
AGENTID=''
for _i in $(seq 1 90); do
    post_auth --data 'action=sw_devices' >/dev/null
    AGENTID=$(jq -r '[.devices[]|select(.online==true)][0].id // empty' "$BODY")
    [ -n "$AGENTID" ] && break
    sleep 2
done
if [ -n "$AGENTID" ]; then ok "the agent shows online in sw_devices ($AGENTID)"; else bad 'no online agent within 3 minutes'; fi
export AG_ENV="$AGENTID"
post_auth --data 'action=sw_devices' >/dev/null
chkjq '...and it is a LINUX device' 'any(.devices[]; .id==env.AG_ENV and .platform=="linux")'
# Arm the collector EXACTLY once: save_settings -> rescheduleAll -> collectAllOnline 20 s later
# and every 60 s after that. Re-arming inside the wait loop would invalidate the previous pass
# (timerGen++), so patience is what we wait with - plus the connect-hook's own stagger timer.
post_auth --data 'action=save_settings' --data 'scanIntervalHours=0' --data 'updateHours=8760' --data 'anyCveMaxAgeYears=5' --data 'collectIntervalMinutes=1' --data 'notifyThreshold=HIGH' --data 'notifyOnScan=true' --data 'notifyUnratedRepeat=false' --data 'autoProductMatch=true' --data 'cpeTableEnabled=true' --data 'distroManaged=true' --data 'osLifecycleEnabled=true' --data 'collectOnAgentConnect=true' --data 'scanMeshes=' --data 'notifyMeshIds=' --data 'notifySeverities=' --data 'cpeTableUrl=' --data 'osLifecycleUrl=' >/dev/null
SWF=''
for _i in $(seq 1 150); do
    SWF=$(ls "$DATA"/plugins/inventoryscanner/data/*/software.json 2>/dev/null | head -n1)
    [ -n "$SWF" ] && break
    sleep 4
done
if [ -n "$SWF" ] && jq -e '((.apps? // .) | type=="array") and ((.apps? // .)|length>0) and (((.apps? // .)[0])|has("name"))' "$SWF" >/dev/null 2>&1; then ok 'the plugin collected a real software list over the agent channel'; else bad 'no collected software.json from the agent'; fi
chk 'software CSV export'                             200 "$(get_auth '&action=export&type=software')"
if grep -qw mag "$BODY"; then ok 'the CSV contains the agent host'; else bad 'agent host missing from CSV'; fi
[ "$(wc -c < "$BODY")" -gt 400 ] && ok 'the CSV carries collected rows' || bad 'CSV still empty after collection'
export GR_ENV="$GROUPID"
chk 'scan the real location'                          200 "$(get_auth "&action=scan&mesh=$GROUPID")"
chkjq '...lists the real device group' 'any(.meshes[]; .id==env.GR_ENV)'
get_auth '&action=deviceReport' >/dev/null
if grep -qw mag "$BODY"; then ok 'the device report contains the agent'; else bad 'agent missing from the device report'; fi
get_auth '&action=report' >/dev/null
if grep -qi 'Vulnerability Report' "$BODY"; then ok 'the vulnerability report still renders with a device'; else bad 'report render regressed with a device'; fi
post_auth --data 'action=os_status' >/dev/null
chkjq '...os_status sees the linux device' 'any(.devices[]; .platform=="linux")'
post_auth --data 'action=wg_status' >/dev/null
chkjq '...winget stays empty (platform gate, real osdesc)' '(.devices|length)==0'
PKG=$(printf '#!/bin/sh\necho deployed-by-inventoryscanner > /tmp/inv-ci-deployed.txt\n' | base64 | tr '+/' '-_' | tr -d '=\n')
chk 'sw_upload commits a .sh installer'               200 "$(post_auth --data 'action=sw_upload' --data 'uploadId=0a0b0c0d0e0f' --data 'name=inv-ci.sh' --data 'index=0' --data-urlencode "data=$PKG" --data 'last=true')"
chkjq '...done + library entry' '.done==true and (.file.id|type=="string") and .file.ext=="sh"'
FILEID=$(jq -r .file.id "$BODY")
chk 'sw_create_task for the agent'                    200 "$(post_auth --data 'action=sw_create_task' --data 'source=library' --data "fileId=$FILEID" --data "nodeIds=$AGENTID")"
chkjq '...task created, one device' 'has("taskId") and (.devices==1)'
TID=$(jq -r .taskId "$BODY")
STATE='pending'
for _i in $(seq 1 90); do
    post_auth --data 'action=sw_status' >/dev/null
    STATE=$(jq -r "[.tasks[]|select(.id==\"$TID\")][0].devices[0].state // \"lost\"" "$BODY")
    case "$STATE" in ok|failed|error|no-file|timeout|unsupported|cancelled) break ;; esac
    sleep 2
done
if [ "$STATE" = 'ok' ]; then ok "the agent ran the deployed package (state ok)"; else bad "deploy ended with state '$STATE'"; fi
post_auth --data 'action=sw_status' >/dev/null
chkjq '...reported exit code 0' "[.tasks[]|select(.id==\"$TID\")][0].devices[0].exit==0"

echo
echo '=================================================='
echo "inventoryscanner vs live MeshCentral: $PASS passed, $FAILS failed"
if [ "$FAILS" -gt 0 ]; then printf 'failed checks:%s\n' "$FAILED_NAMES"; exit 1; fi
