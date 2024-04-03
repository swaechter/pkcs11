dependencies {
    // Testing (General)
    testImplementation(libraries.junit.api)
    testImplementation(libraries.junit.engine)
    testRuntimeOnly(libraries.junit.engine)

    // Testing (PDF signing)
    testImplementation(libraries.slf4j.nop)
    testImplementation(libraries.itext.kernel)
    testImplementation(libraries.itext.io)
    testImplementation(libraries.itext.layout)
    testImplementation(libraries.itext.sign)
    testImplementation(libraries.itext.bouncycastle) {
        exclude(group = "org.bouncycastle", module = "bcpkix-jdk15on")
        exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")
    }
}
