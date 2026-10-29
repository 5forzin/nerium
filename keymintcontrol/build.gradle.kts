plugins { id("com.android.application") }

android {
    namespace = "dev.androidlab.keymintcontrol"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.androidlab.keymintcontrol"
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
