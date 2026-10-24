// Short names for the API's shapes (generated in api-types.ts from the backend's OpenAPI schema).
import type { components } from "@/api-types";

type S = components["schemas"];
export type PlanSummary = S["PlanSummary"];
export type PlanDetail = S["PlanDetail"];
export type PlanList = S["PlanList"];
export type StepView = S["StepView"];
export type Reviewer = S["Reviewer"];
export type DiffRow = S["DiffRowView"];
export type AgentView = S["AgentView"];
export type AgentList = S["AgentList"];
export type AgentToken = S["AgentToken"];
export type EnrollmentView = S["EnrollmentView"];
export type StatusView = S["StatusView"];
export type PolicyView = S["PolicyView"];
export type PolicyPreview = S["PolicyPreview"];
export type PublishResult = S["PublishResultView"];
export type GroupView = S["GroupView"];
export type AuditPage = S["AuditPage"];
export type AuditEntry = S["AuditEntry"];
export type Feed = S["Feed"];
export type FeedItem = S["FeedItem"];
export type SettingsView = S["SettingsView"];
export type PasskeyView = S["PasskeyView"];
export type SessionView = S["SessionView"];
export type OutputView = S["OutputView"];
export type ApproveOptions = S["ApproveOptions"];
export type Me = S["Me"];
