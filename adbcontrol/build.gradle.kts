plugins { id("com.android.application") }

android {
    namespace = "dev.androidlab.adbcontrol"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.androidlab.adbcontrol"
        minSdk = 34
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
