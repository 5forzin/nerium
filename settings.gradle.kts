pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven("https://api.xposed.info/") {
            content { includeGroup("de.robv.android.xposed") }
        }
    }
}

rootProject.name = "nerium"
include(":probe", ":module", ":rawprobe", ":procprobe", ":attestationprobe", ":integrityprobe", ":adbcontrol", ":boundaryprobe", ":relayworker", ":relayrequester")
include(":hostkeyprobe")
include(":keymintcontrol")
include(":cngattestationcontrol")
