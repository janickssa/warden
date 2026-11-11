import SwiftUI
import UIKit
import WardenKit

/// Press and hold for 2 s with haptics (README 17.4: kill switch and lockdown take deliberate effort).
struct HoldButton: View {
    let title: String
    let holding: String
    let systemImage: String
    let action: () -> Void
    @State var progress: CGFloat = 0
    @State var pressing = false

    var body: some View {
        ZStack(alignment: .leading) {
            GeometryReader { g in
                Rectangle().fill(Theme.danger.opacity(0.28)).frame(width: g.size.width * progress)
            }
            Label(pressing ? holding : title, systemImage: systemImage)
                .frame(maxWidth: .infinity, minHeight: 48)
                .foregroundStyle(Theme.danger)
        }
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.danger))
        .contentShape(Rectangle())
        .onLongPressGesture(minimumDuration: 2, maximumDistance: 40) {
            UINotificationFeedbackGenerator().notificationOccurred(.warning)
            progress = 0
            pressing = false
            action()
        } onPressingChanged: { down in
            pressing = down
            if down {
                UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                withAnimation(.linear(duration: 2)) { progress = 1 }
            } else {
                withAnimation(.easeOut(duration: 0.2)) { progress = 0 }
            }
        }
        .accessibilityAddTraits(.isButton)
        .accessibilityHint(holding)
    }
}
