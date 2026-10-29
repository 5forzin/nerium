plugins { id("com.android.application") }

android {
    namespace = "dev.androidlab.cngattestationcontrol"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.androidlab.cngattestationcontrol"
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
