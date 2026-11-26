# Keep gomobile / gobind Java classes and JNI callback interfaces intact under R8 full mode.
-keep class dev.tunssh.mobile.** { *; }
-keep interface dev.tunssh.mobile.** { *; }
-keep class go.** { *; }
-keep interface go.** { *; }
-dontwarn dev.tunssh.mobile.**
-dontwarn go.**
-dontwarn com.google.zxing.**

# Keep Kotlin classes implementing gomobile callback interfaces so JNI method lookup succeeds.
-keepclassmembers class * implements dev.tunssh.mobile.EventListener {
    public void onStatusChanged(java.lang.String);
    public void onHostKeyPrompt(java.lang.String);
    public void onLog(java.lang.String);
}
-keepclassmembers class * implements dev.tunssh.mobile.SocketProtector {
    public boolean protect(int);
}
