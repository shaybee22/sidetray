import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

// Release signing (A4): gen/android/keystore.properties, which git ignores, names
// the keystore and its passwords (storeFile, storePassword, keyAlias, keyPassword).
// CI writes it from GitHub secrets; without it a release build is unsigned.
val keystoreProperties = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) {
        f.inputStream().use { load(it) }
    }
}

// Local test builds only: SIDETRAY_WEBVIEW_DEBUG=1 turns on WebView DevTools in
// a release build (the test phone runs release-signed builds). Such a build also
// carries assets/webview-debug, which the release workflow refuses, and Gradle
// refuses the switch outright under CI.
val webviewDebug = System.getenv("SIDETRAY_WEBVIEW_DEBUG") == "1"
if (webviewDebug && System.getenv("CI") != null) {
    throw GradleException("SIDETRAY_WEBVIEW_DEBUG is for local test builds only, never in CI")
}
val webviewDebugAssets = layout.buildDirectory.dir("generated/webview-debug-assets").get().asFile
if (webviewDebug) {
    val dir = webviewDebugAssets
    dir.mkdirs()
    File(dir, "webview-debug").writeText("WebView DevTools are on in this build. Not for release.\n")
}

android {
    compileSdk = 37
    namespace = "org.sidetray.app"
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        applicationId = "org.sidetray.app"
        minSdk = 24
        targetSdk = 37
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
        buildConfigField("boolean", "WEBVIEW_DEBUG", webviewDebug.toString())
    }
    if (webviewDebug) {
        sourceSets.getByName("main").assets.srcDir(webviewDebugAssets)
    }
    signingConfigs {
        if (keystoreProperties.containsKey("storeFile")) {
            create("release") {
                storeFile = rootProject.file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            }
        }
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {
                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            signingConfigs.findByName("release")?.let { signingConfig = it }
            optimization {
               enable = true
            }
            proguardFiles(
                *fileTree(".") {
                  include("**/*.pro")
                  exclude("build/**")
                }.files.toTypedArray()
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    buildFeatures {
        buildConfig = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_1_8
    }
}

rust {
    rootDirRel = "../../../"
}

dependencies {
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    // A3: UnifiedPush (wake-ups through the ntfy app) and background sync.
    implementation("org.unifiedpush.android:connector:3.3.5")
    implementation("androidx.work:work-runtime-ktx:2.10.1")
    // Phase 9c: video transcoding on the phone's hardware encoder.
    implementation("androidx.media3:media3-transformer:1.11.1")
    implementation("androidx.media3:media3-effect:1.11.1")
    implementation("androidx.media3:media3-common:1.11.1")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

apply(from = file("tauri.build.gradle.kts"))
