import SwiftUI
import UIKit
import WardenCore
import WardenKit

/// Pair this iPhone (DECISIONS M8-01): paste the one-time link from Settings → Pair iPhone in the
/// dashboard (Universal Clipboard from the Mac) or from `warden passkey add iPhone`. Face ID creates the key.
struct PairingView: View {
    @EnvironmentObject var model: AppModel
    @State var link = ""
    @State var busy = false
    @State var error: String?

    var parsed: PairingLink? { PairingLink(link) }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 10) {
                Image(systemName: "checkmark.shield").font(.largeTitle).foregroundStyle(Theme.accent)
                Text("Warden").font(.largeTitle.weight(.medium))
            }
            Text(model.l.t("Pair this iPhone")).font(.title2)
            Text(model.l.t("In the dashboard, open Settings → Passkeys & sessions → Pair iPhone, copy the link and paste it here. Face ID then creates a key that never leaves this iPhone."))
                .font(.subheadline).foregroundStyle(Theme.neutral300)
            TextField("https://warden.example.dk/register?token=…", text: $link, axis: .vertical)
                .font(.footnote.monospaced())
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .padding(10)
                .background(Theme.surface, in: RoundedRectangle(cornerRadius: 8))
            Button(model.l.t("Paste")) { link = UIPasteboard.general.string ?? "" }
            if let error {
                Text(error).font(.footnote).foregroundStyle(Theme.danger)
            }
            Button {
                Task { await pair() }
            } label: {
                Label(busy ? model.l.t("Waiting for Face ID…") : model.l.t("Pair with Face ID"), systemImage: "faceid")
                    .frame(maxWidth: .infinity, minHeight: 44)
            }
            .buttonStyle(.borderedProminent)
            .disabled(parsed == nil || busy)
            Spacer()
            Label(model.l.t("The dashboard is only reachable over WireGuard. Sessions last 12 hours."), systemImage: "lock")
                .font(.caption).foregroundStyle(Theme.neutral500)
        }
        .padding(20)
    }

    func pair() async {
        guard let parsed else { return }
        busy = true
        defer { busy = false }
        do {
            _ = try await Session.pair(parsed, deviceName: UIDevice.current.name)
            model.didPair()
        } catch {
            self.error = model.describe(error)
        }
    }
}
