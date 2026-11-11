import SwiftUI
import WardenCore
import WardenKit

/// Activity (README 17.4): running plans first, then the live feed.
struct ActivityView: View {
    @EnvironmentObject var model: AppModel
    @State var feed: [FeedItem] = []
    @State var running: [PlanDetail] = []

    var body: some View {
        NavigationStack {
            List {
                if !running.isEmpty {
                    Section(model.l.t("Running")) {
                        ForEach(running) { p in
                            NavigationLink(value: p.id) {
                                VStack(alignment: .leading, spacing: 6) {
                                    Text(p.goal).font(.subheadline)
                                    let done = p.stepList.filter { $0.status == "succeeded" }.count
                                    ProgressView(value: Double(done), total: Double(max(p.stepList.count, 1)))
                                    Text(model.l.t("Running step {n} of {total}", ["n": min(done + 1, p.stepList.count), "total": p.stepList.count]))
                                        .font(.caption).foregroundStyle(Theme.accent300)
                                }
                            }
                        }
                    }
                }
                Section(model.l.t("Live feed")) {
                    ForEach(feed) { item in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Text(Format.parse(item.ts).map(Format.time) ?? "").font(.caption.monospacedDigit()).foregroundStyle(Theme.neutral400)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.action).font(.caption.monospaced()).foregroundStyle(Theme.accent300)
                                Text(item.subject).font(.footnote).lineLimit(3)
                                Text([item.actor, item.target].compactMap { $0 }.joined(separator: " · ")).font(.caption2).foregroundStyle(Theme.neutral500)
                            }
                        }
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg)
            .navigationTitle(model.l.t("Activity"))
            .navigationDestination(for: String.self) { PlanView(id: $0) }
            .refreshable { await load() }
            .task {
                while !Task.isCancelled {
                    await load()
                    try? await Task.sleep(for: .seconds(5))
                }
            }
        }
    }

    func load() async {
        guard let s = model.session else { return }
        if let f = try? await s.read({ try await $0.feed() }) { feed = f.items }
        var plans: [PlanDetail] = []
        for id in model.status?.running ?? [] {
            if let p = try? await s.read({ try await $0.plan(id) }) { plans.append(p) }
        }
        running = plans
    }
}
