plugins { id("com.android.application") }

android {
    namespace = "dev.androidlab.relayworker"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.androidlab.relayworker"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies { implementation("com.google.android.play:integrity:1.6.0") }
