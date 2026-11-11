import SwiftUI
import WardenCore
import WardenKit

struct RootView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Group {
            if model.paired {
                TabView(selection: $model.tab) {
                    ApprovalsView()
                        .tabItem { Label(model.l.t("Approvals"), systemImage: "tray") }
                        .badge(model.status?.awaiting ?? 0)
                        .tag(0)
                    ActivityView()
                        .tabItem { Label(model.l.t("Activity"), systemImage: "waveform.path.ecg") }
                        .tag(1)
                    SchedulesView()
                        .tabItem { Label(model.l.t("Schedules"), systemImage: "clock.arrow.circlepath") }
                        .badge(model.status?.schedulesAwaiting ?? 0)
                        .tag(2)
                    SettingsView()
                        .tabItem { Label(model.l.t("Settings"), systemImage: "gearshape") }
                        .tag(3)
                }
                .safeAreaInset(edge: .top) { Banners() }
            } else {
                PairingView()
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .onAppear { model.start() }
    }
}

/// Offline and lockdown banners (spec 1.4), above every tab.
struct Banners: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            if model.offline {
                HStack(spacing: 8) {
                    Image(systemName: "wifi.slash").foregroundStyle(Theme.warn)
                    VStack(alignment: .leading) {
                        Text(model.l.t("Can’t reach Warden. Is WireGuard connected?")).font(.footnote)
                        if let at = model.lastUpdated {
                            Text(model.l.t("Stale · last updated {time}", ["time": Format.time(at)])).font(.caption2).foregroundStyle(Theme.neutral400)
                        }
                    }
                    Spacer()
                }
                .padding(10)
                .background(Theme.warn.opacity(0.12))
            }
            if model.status?.lockdown == true {
                HStack(spacing: 8) {
                    Image(systemName: "lock.fill").foregroundStyle(Theme.danger)
                    Text(model.l.t("■ Lockdown active")).font(.footnote).foregroundStyle(Theme.danger)
                    Spacer()
                }
                .padding(10)
                .background(Theme.danger.opacity(0.14))
            }
        }
    }
}
