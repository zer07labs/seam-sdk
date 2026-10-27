plugins {
    kotlin("jvm") version "2.0.20"
}

repositories { mavenCentral() }

dependencies {
    // Ed25519 seed→pubkey + raw sign/verify.
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

kotlin { jvmToolchain(17) }

tasks.test {
    useJUnitPlatform()
    // MgmtDpopTest runs the README's DPoP snippet, which reads these two variables: the PUBLIC test-vector key
    // (seed 0x42 x 32, conformance/mgmt_dpop_vector.json) and a token bound to it. Neither is a real secret.
    environment("SEAM_OPERATOR_DPOP_JWK", """{"kty":"OKP","crv":"Ed25519","x":"IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI","d":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"}""")
    environment("SEAM_OPERATOR_TOKEN", "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJzZWFtLXJ1bnRpbWUiLCJzdWIiOiJyZWFkbWUiLCJjbmYiOnsiamt0IjoibkVBcnBqRzNrWU1jeGJkeklueUdsQkVZUVV3N1JmQWZlM1R3MWZadkFBMCJ9fQ.c2ln")
}
