plugins { id("com.android.application") }

android {
    namespace = "dev.androidlab.module"
    compileSdk = 35
    ndkVersion = "27.0.12077973"
    defaultConfig {
        applicationId = "dev.androidlab.module"
        minSdk = 28
        targetSdk = 35
        versionCode = 15
        versionName = "0.12.2"
        ndk { abiFilters += listOf("x86_64", "arm64-v8a") }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

