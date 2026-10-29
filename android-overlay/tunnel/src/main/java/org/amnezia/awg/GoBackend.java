package org.amnezia.awg;

import androidx.annotation.Nullable;

public class GoBackend {
    @Nullable
    public static native String awgGetConfig(int handle);

    public static native int awgGetSocketV4(int handle);

    public static native int awgGetSocketV6(int handle);

    public static native void awgTurnOff(int handle);

    public static native int awgTurnOn(String ifName, int tunFd, String settings);

    public static native String awgVersion();

    @Nullable public static native String awgGetInterfaceName(int handle);
    public static native long r013PrimaryBegin();
    public static native int r013PrimaryEnd(long ticket);
    public static native int awgTurnOnGuarded(long ticket, String ifName, int tunFd, String settings);
    public static native int awgTurnOffGuarded(long ticket, int handle);
    public static native long r013ProbeCreate(Object transportGate);
    public static native void r013ProbeInvalidate(long scope);
    public static native int r013ProbeRefresh(long scope);
    public static native long r013ProbeStart(long scope, String snapshotsJSON);
    @Nullable public static native String r013ProbePoll(long scope, long operation);
    public static native long r013ProbeChoose(long scope, long operation, String freshChoiceJSON);
    public static native int r013ProbeRelease(long scope);
    public static native int r013ProxyStart(long ticket, String configuration, int fd, Object gate);
    public static native int r013ProxyStop(long ticket);
    @Nullable public static native String r013ProxyStats();
    public static native long r013ProxyProbe(String configuration, Object gate);
}
