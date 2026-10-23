from pathlib import Path
p=Path('WireGuard.xcodeproj/project.pbxproj');text=p.read_text()
objects='''
A01300000000000000000001 = {isa=PBXFileReference;lastKnownFileType=sourcecode.swift;path=VPN013/UITests.swift;sourceTree=SOURCE_ROOT;};
A01300000000000000000002 = {isa=PBXBuildFile;fileRef=A01300000000000000000001;};
A01300000000000000000003 = {isa=PBXSourcesBuildPhase;buildActionMask=2147483647;files=(A01300000000000000000002,);runOnlyForDeploymentPostprocessing=0;};
A01300000000000000000004 = {isa=PBXFrameworksBuildPhase;buildActionMask=2147483647;files=();runOnlyForDeploymentPostprocessing=0;};
A01300000000000000000005 = {isa=PBXResourcesBuildPhase;buildActionMask=2147483647;files=();runOnlyForDeploymentPostprocessing=0;};
A01300000000000000000006 = {isa=PBXFileReference;explicitFileType=wrapper.cfbundle;includeInIndex=0;path=AutoTunnelUITests.xctest;sourceTree=BUILT_PRODUCTS_DIR;};
A01300000000000000000007 = {isa=XCBuildConfiguration;buildSettings={CODE_SIGNING_ALLOWED=NO;GENERATE_INFOPLIST_FILE=YES;IPHONEOS_DEPLOYMENT_TARGET=15.0;PRODUCT_BUNDLE_IDENTIFIER=com.vpn013.awg.uitests;PRODUCT_NAME="$(TARGET_NAME)";SDKROOT=iphoneos;SWIFT_VERSION=5.0;TARGETED_DEVICE_FAMILY="1,2";TEST_TARGET_NAME=WireGuardiOS;};name=Debug;};
A01300000000000000000008 = {isa=XCConfigurationList;buildConfigurations=(A01300000000000000000007,);defaultConfigurationIsVisible=0;defaultConfigurationName=Debug;};
A01300000000000000000009 = {isa=PBXContainerItemProxy;containerPortal=6FF4AC0C211EC46F002C96EB;proxyType=1;remoteGlobalIDString=6FF4AC13211EC46F002C96EB;remoteInfo=WireGuardiOS;};
A0130000000000000000000A = {isa=PBXTargetDependency;target=6FF4AC13211EC46F002C96EB;targetProxy=A01300000000000000000009;};
A0130000000000000000000B = {isa=PBXNativeTarget;buildConfigurationList=A01300000000000000000008;buildPhases=(A01300000000000000000003,A01300000000000000000004,A01300000000000000000005,);buildRules=();dependencies=(A0130000000000000000000A,);name=AutoTunnelUITests;productName=AutoTunnelUITests;productReference=A01300000000000000000006;productType="com.apple.product-type.bundle.ui-testing";};
'''
text=text.replace('objects = {','objects = {'+objects,1)
anchor='\t\t\ttargets = (';assert text.count(anchor)==1;text=text.replace(anchor,anchor+'\n\t\t\t\tA0130000000000000000000B,')
p.write_text(text)
scheme='''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1600" version="1.3">
<BuildAction parallelizeBuildables="NO" buildImplicitDependencies="YES"><BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="NO" buildForArchiving="YES" buildForAnalyzing="YES"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="6FF4AC13211EC46F002C96EB" BuildableName="AmneziaWG.app" BlueprintName="WireGuardiOS" ReferencedContainer="container:WireGuard.xcodeproj"/></BuildActionEntry></BuildActionEntries></BuildAction>
<TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES"><Testables><TestableReference skipped="NO"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="A0130000000000000000000B" BuildableName="AutoTunnelUITests.xctest" BlueprintName="AutoTunnelUITests" ReferencedContainer="container:WireGuard.xcodeproj"/></TestableReference></Testables><MacroExpansion><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="6FF4AC13211EC46F002C96EB" BuildableName="AmneziaWG.app" BlueprintName="WireGuardiOS" ReferencedContainer="container:WireGuard.xcodeproj"/></MacroExpansion></TestAction>
<LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" debugServiceExtension="internal" allowLocationSimulation="YES"><BuildableProductRunnable runnableDebuggingMode="0"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="6FF4AC13211EC46F002C96EB" BuildableName="AmneziaWG.app" BlueprintName="WireGuardiOS" ReferencedContainer="container:WireGuard.xcodeproj"/></BuildableProductRunnable></LaunchAction>
<ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/></Scheme>'''
out=Path('WireGuard.xcodeproj/xcshareddata/xcschemes');out.mkdir(parents=True,exist_ok=True);(out/'VPN013Auto.xcscheme').write_text(scheme)
