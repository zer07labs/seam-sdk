plugins {
    `java-library`
}

repositories { mavenCentral() }

dependencies {
    // Ed25519 seed→pubkey + raw sign/verify (java.security can't derive a pubkey from a raw seed).
    api("org.bouncycastle:bcprov-jdk18on:1.78.1")
    // JSON for JWS header/payload + the conformance vectors.
    api("com.google.code.gson:gson:2.11.0")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(17) }
}

tasks.test { useJUnitPlatform() }
