"""Bounded sequential screenshots on disposable CI simulators. No physical device."""
from pathlib import Path
import json,os,plistlib,subprocess,time,uuid,zlib

def main():
    assert os.environ.get("GITHUB_ACTIONS")=="true"
    assert os.environ.get("GITHUB_REPOSITORY")=="2njz45z86r-commits/vpn013-wg-ios"
    root=Path.cwd().resolve();review=root/"build/review"
    app=root/"build/SimulatorDerivedData/Build/Products/Debug-iphonesimulator/AmneziaWG.app"
    meta=plistlib.loads((app/"Info.plist").read_bytes())
    settings = dict(line.split(' = ', 1) for line in (root/'overlay/Sources/WireGuardApp/Config/Version.xcconfig').read_text().splitlines() if ' = ' in line)
    assert meta["CFBundleIdentifier"]=="com.vpn013.awg" and meta["CFBundleShortVersionString"]==settings['VERSION_NAME'] and str(meta["CFBundleVersion"])==settings['VERSION_ID_IOS']
    assert (app/meta["CFBundleExecutable"]).is_file()
    def call(*args,limit=90):
        return subprocess.check_output(["xcrun","simctl",*args],text=True,timeout=limit,stderr=subprocess.STDOUT)
    def devices():
        return [dict(d,runtime=runtime) for runtime,rows in json.loads(call("list","devices","available","-j"))["devices"].items() for d in rows]
    available=devices()
    selected=next(d for d in available if d["name"]=="iPhone 16 Pro" and (not os.environ.get('VPN013_CAPTURE_PHONE_ID') or d['udid']==os.environ['VPN013_CAPTURE_PHONE_ID']))
    phone=call('create','VPN013 Review Phone '+uuid.uuid4().hex[:8],selected['deviceTypeIdentifier'],selected['runtime']).strip()
    tablet_template=next(d for d in available if d["name"].startswith("iPad") and d['runtime']==selected['runtime'])
    # A fresh disposable tablet avoids persisted simulator launch services state.
    tablet=call('create','VPN013 Review Tablet '+uuid.uuid4().hex[:8],tablet_template['deviceTypeIdentifier'],selected['runtime']).strip()
    assert phone!=tablet and all(str(uuid.UUID(d)).upper()==d.upper() for d in (phone,tablet))
    def stage(label):
        print("Simulator capture stage="+label,flush=True)
    def shutdown(device):
        if next(d["state"] for d in devices() if d["udid"]==device)!="Shutdown":
            call("shutdown",device,limit=45)
    def boot(device):
        if next(d["state"] for d in devices() if d["udid"]==device)!="Booted":
            call("boot",device,limit=45)
        call("bootstatus",device,"-b",limit=180)
    def launch(device,args):
        # Terminate independently: a new foreground launch must not reuse a
        # previous test application's launch-services transaction.
        subprocess.run(['xcrun','simctl','terminate',device,'com.vpn013.awg'],capture_output=True,timeout=45)
        call("launch",device,"com.vpn013.awg",
             "-AppleLanguages","(ru)","-AppleLocale","ru_RU",*args,limit=90)
        time.sleep(3)
    def screenshot(device,name):
        path=review/name
        call("io",device,"screenshot",str(path),limit=45)
        b=path.read_bytes()
        assert 10000<len(b)<15000000 and b.startswith(b"\x89PNG\r\n\x1a\n")
        width,height=int.from_bytes(b[16:20],"big"),int.from_bytes(b[20:24],"big")
        assert width>=300 and height>=300
        chunks=[];position=8
        while position<len(b):
            size=int.from_bytes(b[position:position+4],'big');kind=b[position+4:position+8]
            assert size<=len(b)-position-12
            if kind==b'IDAT':chunks.append(b[position+8:position+8+size])
            position+=size+12
        decoder=zlib.decompressobj();pixels=decoder.decompress(b''.join(chunks),64*1024*1024)
        assert decoder.eof and not decoder.unconsumed_tail,'Oversized/incomplete screenshot pixels'
        assert len(set(pixels))>16,'Blank/unrendered simulator screenshot is not appearance evidence'
    fixture=["--vpn013-test-count","2","--vpn013-test-current-card","--vpn013-test-start-current","--vpn013-test-ping-loopback"]
    def unified(device,prefix):
        for kind in ('happ','incy','blacktemple'):
            launch(device,["--vpn013-test-unified","--vpn013-test-automatic","--vpn013-test-auto-reset","-VPN013SelectedKind",kind])
            screenshot(device,prefix+'-unified-'+kind+'.png')
        call('ui',device,'content_size','accessibility-extra-extra-extra-large',limit=45)
        try:
            launch(device,["--vpn013-test-unified","--vpn013-test-automatic","--vpn013-test-auto-reset","-VPN013SelectedKind","blacktemple"])
            screenshot(device,prefix+'-unified-large-type.png')
        finally:call('ui',device,'content_size','large',limit=45)
    def cross(device,prefix):
        for large in (False,True):
            call('ui',device,'content_size','accessibility-extra-extra-extra-large' if large else 'large',limit=45)
            launch(device,['--vpn013-test-count','2','--vpn013-test-unified','--vpn013-test-cross-runtime','--vpn013-test-auto-reset'])
            screenshot(device,prefix+'-cross-protocol'+('-large-type' if large else '')+'.png')
        call('ui',device,'content_size','large',limit=45)
    stage("phone-large-type")
    shutdown(selected['udid'])
    try:
        boot(phone)
        call('install',phone,str(app),limit=90)
        call("ui",phone,"content_size","accessibility-extra-extra-extra-large",limit=45)
        launch(phone,fixture);screenshot(phone,"phone-large-type.png")
        call("ui",phone,"content_size","large",limit=45)
        stage("phone-unified-sections")
        unified(phone,'phone')
        cross(phone,'phone')
        stage("phone-ordinary-launch")
        launch(phone,[]);screenshot(phone,"phone-normal-launch-no-fixture.png")
    finally:
        shutdown(phone)
    # Only one job-owned simulator runs at a time. A failed tablet attempt is
    # reset once, then must genuinely produce the required new screenshot.
    for attempt in range(2):
        stage("tablet-attempt-"+str(attempt+1))
        try:
            shutdown(tablet);boot(tablet)
            call("ui",tablet,"appearance","dark",limit=45)
            call("install",tablet,str(app),limit=90)
            launch(tablet,fixture);screenshot(tablet,"tablet.png")
            stage('tablet-unified-sections')
            unified(tablet,'tablet')
            cross(tablet,'tablet')
            break
        except (subprocess.TimeoutExpired,subprocess.CalledProcessError):
            stage("tablet-reset-after-bounded-failure")
            if attempt==1:raise
            # Recreate once rather than retrying the same hung launch state.
            shutdown(tablet);call('delete',tablet,limit=45)
            tablet=call('create','VPN013 Review Tablet '+uuid.uuid4().hex[:8],tablet_template['deviceTypeIdentifier'],selected['runtime']).strip()
        finally:
            shutdown(tablet)
    (review/"simulator-capture-completion.json").write_text(json.dumps({
        "version":meta["CFBundleShortVersionString"],"build":meta["CFBundleVersion"],
        "freshPhoneLargeType":True,"freshPhoneOrdinaryLaunch":True,"freshTablet":True,
        "freshUnifiedPhone":True,"freshUnifiedTablet":True,"freshUnifiedLargeType":True,
        "freshCrossProtocolPhone":True,"freshCrossProtocolTablet":True,"freshCrossProtocolLargeType":True,
        "sequentialSimulators":True,"physicalIPhoneTested":False},indent=2))
    stage("complete")
    call('delete',phone,limit=45)
    call('delete',tablet,limit=45)
if __name__=="__main__":main()
