plugins {
    java
    alias(libs.plugins.defaults)
    alias(libs.plugins.spotless)
}

group = "com.hivemq.extensions.enterprise.security.customizations"
description = "Hello World Customization for the HiveMQ Enterprise Security Extension"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

tasks.compileJava {
    javaCompiler = javaToolchains.compilerFor {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(libs.hivemq.enterpriseSecurityExtension.customizationSdk)
    compileOnly(libs.jetbrains.annotations)
}

@Suppress("UnstableApiUsage")
testing {
    suites {
        withType<JvmTestSuite> {
            useJUnitJupiter(libs.versions.junit.jupiter)
            targets.configureEach {
                testTask {
                    jvmArgs("--enable-native-access=ALL-UNNAMED", "--sun-misc-unsafe-memory-access=allow")
                }
            }
        }
        "test"(JvmTestSuite::class) {
            dependencies {
                implementation(libs.assertj)
                implementation(libs.hivemq.mqttClient)
                implementation(libs.mockserver.client)
                implementation(libs.testcontainers.mockserver)
                implementation(libs.shrinkwrap.api)
                runtimeOnly(libs.shrinkwrap.impl)
                implementation(libs.testcontainers.hivemq)
                implementation(libs.testcontainers.junitJupiter)
            }
        }
    }
}

tasks.withType<Jar>().configureEach {
    manifest.attributes(
        "Implementation-Title" to project.name,
        "Implementation-Vendor" to "HiveMQ GmbH",
        "Implementation-Version" to project.version,
    )
}

spotless {
    java {
        licenseHeaderFile(rootDir.resolve("HEADER"))
    }
}
