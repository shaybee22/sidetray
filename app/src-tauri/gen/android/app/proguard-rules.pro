# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# Side Tray: Rust calls SideTrayAndroid's methods over JNI by name, and the
# native* functions are looked up by their Java names. Keep the app's own
# classes as they are (R8 would otherwise rename or drop them).
-keep class org.sidetray.app.** { *; }

# WorkManager (the background sync) opens its Room database through the
# generated WorkDatabase_Impl, created by reflection: keep the constructors of
# Room databases, or a release build crashes at launch.
-keep class * extends androidx.room.RoomDatabase { <init>(); }
