5.1 Tokens stored in the Keychain, never in `UserDefaults`

final class KeychainHelper {
    static let shared = KeychainHelper()
    private init() {}
 
    func save(_ data: String, service: String, account: String) {
        let data = Data(data.utf8)
        let query = [
            kSecValueData: data,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecClass: kSecClassGenericPassword
        ] as CFDictionary
 
        SecItemDelete(query)   // avoid duplicate-item errors on update
        SecItemAdd(query, nil)
    }
 
    func get(service: String, account: String) -> String? {
        let query = [
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecClass: kSecClassGenericPassword,
            kSecReturnData: true
        ] as CFDictionary
 
        var result: AnyObject?
        SecItemCopyMatching(query, &result)
        guard let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
 
    func clearAllUserData() {
        delete(service: "accessToken")
        delete(service: "refreshToken")
    }
}

Why it matters: access/refresh tokens are sensitive, long-lived credentials. UserDefaults is a plist on disk with no encryption; the Keychain is hardware-backed on-device encrypted storage — the correct place for auth tokens, not "convenient" local storage.


5.2 Client-side JWT expiry parsing to pre-empt using a dead token


struct JWTHelper {
    static func decodeTokenExpiry(_ token: String) -> Date? {
        let segments = token.components(separatedBy: ".")
        guard segments.count > 1 else { return nil }
 
        var base64 = segments[1]
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64.append("=") }
 
        guard let data = Data(base64Encoded: base64),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let exp = json["exp"] as? TimeInterval else { return nil }
 
        return Date(timeIntervalSince1970: exp)
    }
}

Why it matters: the app only decodes the JWT payload locally to read exp — it never trusts the client-side decode as proof of a valid signature (that's the server's job). Decoding expiry client-side just avoids sending obviously-dead tokens and drives the proactive-refresh logic in §3.3.


5.3 Automatic session termination on `401` — no endpoint has to remember to handle it


switch httpResponse.statusCode {
case 200...299:
    return try JSONDecoder().decode(T.self, from: data)
case 401:
    Task { @MainActor in SessionManager.shared.terminateSession() }
    throw NetworkError.unauthorized
default:
    throw NetworkError.serverError("Status code: \(httpResponse.statusCode)")
}

Why it matters: this lives once, in NetworkService, the single chokepoint every API call passes through — so a revoked/expired token can never silently leave the app in a logged-in-looking-but-broken state, regardless of which of the 300+ screens triggered the call.

5.4 Inactivity timeout — forced logout after idle time, independent of token expiry

private let inactivityThreshold: TimeInterval = 20 * 60   // 20 minutes idle
private let warningThreshold: TimeInterval = (19 * 60) + 40
 
private func checkInactivity() {
    let elapsed = Date().timeIntervalSince(lastActivityDate)
    if elapsed >= inactivityThreshold {
        showLogoutInactivityMessage = true
        terminateSession()
    } else if elapsed >= warningThreshold {
        startCountdown(initial: Int(inactivityThreshold - elapsed))
    }
}

Why it matters: a stolen/unlocked device with a still-valid access token is a real risk — the idle-timeout logout (with a visible warning + countdown before it happens) is a defense-in-depth control that's independent of whether the underlying JWT has technically expired yet.

5.5 Input validation before it reaches the network layer
enum Validator {
    static func isValidEmail(_ email: String) -> Bool {
        let emailRegEx = "[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,64}"
        return NSPredicate(format: "SELF MATCHES %@", emailRegEx).evaluate(with: email)
    }
 
    static func isValidUAEMobile(_ mobile: String) -> Bool {
        let regex = #"^(?:\+971|971|0)?5[0-9]{8}$"#
        return NSPredicate(format: "SELF MATCHES %@", regex).evaluate(with: mobile)
    }
}

Note: this is client-side UX validation (fast feedback, fewer bad requests) — it is not a substitute for server-side validation, which must always be the actual security boundary. Worth calling out explicitly in review so junior engineers don't treat Validator as sufficient input sanitization on its own.
