"""Bounded sequential screenshots on disposable CI simulators. No physical device."""
from pathlib import Path
import json,os,plistlib,subprocess,time,uuid

def main():
    assert os.environ.get("GITHUB_ACTIONS")=="true"
    assert os.environ.get("GITHUB_REPOSITORY")=="2njz45z86r-commits/vpn013-wg-ios"
    root=Path.cwd().resolve();review=root/"build/review"
    app=root/"build/SimulatorDerivedData/Build/Products/Debug-iphonesimulator/AmneziaWG.app"
    meta=plistlib.loads((app/"Info.plist").read_bytes())
    assert meta["CFBundleIdentifier"]=="com.vpn013.awg" and meta["CFBundleShortVersionString"]=="1.5.9" and str(meta["CFBundleVersion"])=="21"
    assert (app/meta["CFBundleExecutable"]).is_file()
    def call(*args,limit=90):
        return subprocess.check_output(["xcrun","simctl",*args],text=True,timeout=limit,stderr=subprocess.STDOUT)
    def devices():
        return [d for rows in json.loads(call("list","devices","available","-j"))["devices"].values() for d in rows]
    available=devices()
    phone=next(d["udid"] for d in available if d["name"]=="iPhone 16 Pro")
    tablet=next(d["udid"] for d in available if d["name"].startswith("iPad"))
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
        call("launch","--terminate-running-process",device,"com.vpn013.awg",
             "-AppleLanguages","(ru)","-AppleLocale","ru_RU",*args,limit=90)
        time.sleep(3)
    def screenshot(device,name):
        path=review/name
        call("io",device,"screenshot",str(path),limit=45)
        b=path.read_bytes()
        assert 10000<len(b)<15000000 and b.startswith(b"\x89PNG\r\n\x1a\n")
        width,height=int.from_bytes(b[16:20],"big"),int.from_bytes(b[20:24],"big")
        assert width>=300 and height>=300
    fixture=["--vpn013-test-count","2","--vpn013-test-current-card","--vpn013-test-start-current","--vpn013-test-ping-loopback"]
    stage("phone-large-type")
    try:
        boot(phone)
        call("ui",phone,"content_size","accessibility-extra-extra-extra-large",limit=45)
        launch(phone,fixture);screenshot(phone,"phone-large-type.png")
        call("ui",phone,"content_size","large",limit=45)
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
            break
        except (subprocess.TimeoutExpired,subprocess.CalledProcessError):
            stage("tablet-reset-after-bounded-failure")
            if attempt==1:raise
        finally:
            shutdown(tablet)
    (review/"simulator-capture-completion.json").write_text(json.dumps({
        "version":meta["CFBundleShortVersionString"],"build":meta["CFBundleVersion"],
        "freshPhoneLargeType":True,"freshPhoneOrdinaryLaunch":True,"freshTablet":True,
        "sequentialSimulators":True,"physicalIPhoneTested":False},indent=2))
    stage("complete")
if __name__=="__main__":main()
