plugins { id("com.android.application") }

android {
    namespace = "dev.androidlab.attestationprobe"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.androidlab.attestationprobe"
        minSdk = 28
        targetSdk = 35
        versionCode = 3
        versionName = "0.2.1"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
