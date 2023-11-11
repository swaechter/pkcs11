rootProject.name = "pkcs11"

dependencyResolutionManagement {
    versionCatalogs {
        create("libraries") {
            // Testing
            library("junit-api", "org.junit.jupiter:junit-jupiter-api:5.10.0")
            library("junit-engine", "org.junit.jupiter:junit-jupiter-engine:5.10.0")
        }
    }
}
