plugins {
    kotlin("jvm") version "2.0.20"
}

repositories { mavenCentral() }

dependencies {
    // Ed25519 seed→pubkey + raw sign/verify.
    api("org.bouncycastle:bcprov-jdk18on:1.78.1")
    // JSON for JWS header/payload + the conformance vectors.
    api("com.google.code.gson:gson:2.11.0")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin { jvmToolchain(17) }

tasks.test { useJUnitPlatform() }
