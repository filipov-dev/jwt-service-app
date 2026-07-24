// Swift — библиотека: SwiftOTP (SPM: apple/swift-crypto-based)
import Foundation
import SwiftOTP

let secret = ProcessInfo.processInfo.environment["AUTH_TOTP_SECRET"]!     // base32
let service = ProcessInfo.processInfo.environment["JWT_SERVICE_URL"] ?? "http://localhost:8080"

let totp = TOTP(secret: base32DecodeToData(secret)!, digits: 6, timeInterval: 30, algorithm: .sha1)!
let code = totp.generate(time: Date())!

var req = URLRequest(url: URL(string: "\(service)/tokens")!)
req.httpMethod = "POST"
req.setValue(code, forHTTPHeaderField: "X-TOTP-Code")
req.setValue("example.com", forHTTPHeaderField: "Host")
req.setValue("application/json", forHTTPHeaderField: "Content-Type")
req.httpBody = #"{"sub":"svc-a","aud":["svc-b"]}"#.data(using: .utf8)

let (data, resp) = try await URLSession.shared.data(for: req)
print((resp as! HTTPURLResponse).statusCode, String(data: data, encoding: .utf8)!)
