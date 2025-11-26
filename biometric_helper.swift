import Foundation
import LocalAuthentication

let context = LAContext()
var error: NSError?

if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
    let reason = "Authenticate to unlock Secure Chat"

    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                           localizedReason: reason) { success, authError in
        if success {
            print("OK")
            fflush(stdout)
            exit(EXIT_SUCCESS)
        } else {
            fputs("Authentication failed\n", stderr)
            exit(EXIT_FAILURE)
        }
    }

    RunLoop.main.run()
} else if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
    let reason = "Authenticate to unlock Secure Chat"

    context.evaluatePolicy(.deviceOwnerAuthentication,
                           localizedReason: reason) { success, authError in
        if success {
            print("OK")
            fflush(stdout)
            exit(EXIT_SUCCESS)
        } else {
            fputs("Authentication failed\n", stderr)
            exit(EXIT_FAILURE)
        }
    }

    RunLoop.main.run()
} else {
    fputs("Biometric / device authentication not available\n", stderr)
    exit(EXIT_FAILURE)
}