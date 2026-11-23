plugins {
    kotlin("jvm") version "2.3.20"
}

group = "xyz.audren"
version = "1.2.1"

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.java.dev.jna:jna:5.15.0")

    testImplementation(kotlin("test"))
    testImplementation("org.json:json:20250107")
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform()
    val ffiLibDir = System.getenv("AUDREN_FFI_LIB_DIR")
        ?: file("../../target/release").canonicalPath
    systemProperty("jna.library.path", ffiLibDir)
    testLogging {
        events("passed", "skipped", "failed")
    }
}
