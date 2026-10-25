plugins {
    `java-library`
}

repositories { mavenCentral() }

dependencies {
    // Ed25519 seed→pubkey + raw sign/verify (java.security can't derive a pubkey from a raw seed).
    api("org.bouncycastle:bcprov-jdk18on:1.78.1")
    // JSON for JWS header/payload + the conformance vectors.
    api("com.google.code.gson:gson:2.11.0")
    // The x-seam-tenant interceptor and the ErrorInfo / WRONG_CELL reader (k8s P15, D123). A floor:
    // Gradle resolves to the caller's own newer grpc-java when it has one.
    api("io.grpc:grpc-api:1.66.0")
    api("io.grpc:grpc-protobuf:1.66.0")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("io.grpc:grpc-inprocess:1.66.0")
    testImplementation("io.grpc:grpc-stub:1.66.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(17) }
}

tasks.test { useJUnitPlatform() }
