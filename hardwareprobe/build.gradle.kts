plugins { id("com.android.application") }

android {
    namespace = "dev.androidlab.hardwareprobe"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.androidlab.hardwareprobe"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "dev.androidlab.hardwareprobe.SnapshotRunner"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
