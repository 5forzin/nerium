plugins { id("com.android.application") }

android {
    namespace = "dev.androidlab.relayrequester"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.androidlab.relayrequester"
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
