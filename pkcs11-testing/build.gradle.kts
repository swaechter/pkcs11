dependencies {
    // Project
    testImplementation(project(":pkcs11-cli"))
    testImplementation(project(":pkcs11-library"))

    // Testing (General)
    testImplementation(libraries.junit.api)
    testImplementation(libraries.junit.engine)
    testRuntimeOnly(libraries.junit.engine)
}
