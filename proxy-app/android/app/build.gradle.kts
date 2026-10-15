plugins {
    id("com.android.application")
}

android {
    namespace = "com.transproxy.client"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.transproxy.client"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
        debug {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        // AGP 8 起 BuildConfig 默认不生成，需要显式打开。
        // 用它区分调试包/正式包：调试包把内核日志开到 info，便于排查。
        buildConfig = true
    }

    // 内核 .so 每个架构约 60MB，三个架构全塞一个包里会到 200MB 以上。
    // 按 ABI 拆包后真机只需装 arm64 那个；同时保留 universal 包，
    // 方便不想挑架构时直接装。
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            isUniversalApk = true
        }
    }

    packaging {
        jniLibs {
            // 内核的 .so 不能被压缩：压缩后加载时无法直接映射，会启动失败。
            useLegacyPackaging = false
        }
    }

    // 分流数据文件也保持不压缩：运行时要把它们原样拷到私有目录，
    // 压缩过的条目读出来还要再解一次，白白多一层出错可能。
    androidResources {
        noCompress += listOf("dat")
    }
}

dependencies {
    // 内核（xray + gVisor）由 gomobile 编译成 AAR，随应用打包。
    implementation(files("libs/xraycore.aar"))
}
