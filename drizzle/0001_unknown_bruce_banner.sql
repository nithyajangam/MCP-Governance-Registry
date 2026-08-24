CREATE TABLE `approvalRequests` (
	`id` varchar(64) NOT NULL,
	`tenantId` varchar(64) NOT NULL,
	`serverId` varchar(64) NOT NULL,
	`toolId` varchar(64) NOT NULL,
	`requestHash` varchar(64) NOT NULL,
	`requestedBy` varchar(160) NOT NULL,
	`argumentsRedacted` text NOT NULL,
	`status` enum('pending','approved','rejected','expired') NOT NULL DEFAULT 'pending',
	`reviewer` varchar(160),
	`decisionNote` text,
	`expiresAt` timestamp NOT NULL,
	`decidedAt` timestamp,
	`consumedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `approvalRequests_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `auditEvents` (
	`id` varchar(64) NOT NULL,
	`tenantId` varchar(64) NOT NULL,
	`eventType` varchar(120) NOT NULL,
	`actor` varchar(160) NOT NULL,
	`resource` varchar(160) NOT NULL,
	`outcome` varchar(64) NOT NULL,
	`correlationId` varchar(96) NOT NULL,
	`details` text NOT NULL,
	`previousHash` varchar(64) NOT NULL,
	`eventHash` varchar(64) NOT NULL,
	`createdAt` timestamp NOT NULL,
	CONSTRAINT `auditEvents_id` PRIMARY KEY(`id`),
	CONSTRAINT `auditEvents_hash_idx` UNIQUE(`eventHash`)
);
--> statement-breakpoint
CREATE TABLE `mcpServers` (
	`id` varchar(64) NOT NULL,
	`tenantId` varchar(64) NOT NULL,
	`name` varchar(160) NOT NULL,
	`namespace` varchar(220) NOT NULL,
	`description` text NOT NULL,
	`endpointUrl` varchar(512) NOT NULL,
	`capabilityUrl` varchar(512) NOT NULL,
	`transport` varchar(64) NOT NULL DEFAULT 'streamable-http',
	`ownerTeam` varchar(120) NOT NULL,
	`slo` varchar(120) NOT NULL,
	`status` enum('active','disabled','needs_review') NOT NULL DEFAULT 'active',
	`validationStatus` enum('valid','warning','invalid') NOT NULL DEFAULT 'valid',
	`lastValidatedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `mcpServers_id` PRIMARY KEY(`id`),
	CONSTRAINT `mcpServers_namespace_idx` UNIQUE(`namespace`)
);
--> statement-breakpoint
CREATE TABLE `mcpTools` (
	`id` varchar(64) NOT NULL,
	`serverId` varchar(64) NOT NULL,
	`tenantId` varchar(64) NOT NULL,
	`name` varchar(160) NOT NULL,
	`description` text NOT NULL,
	`riskLevel` enum('read_only','sensitive','destructive') NOT NULL,
	`requiredScope` varchar(160) NOT NULL,
	`maxPayloadBytes` int NOT NULL DEFAULT 4096,
	`inputSchema` text NOT NULL,
	`isEnabled` boolean NOT NULL DEFAULT true,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `mcpTools_id` PRIMARY KEY(`id`),
	CONSTRAINT `mcpTools_server_name_idx` UNIQUE(`serverId`,`name`)
);
--> statement-breakpoint
CREATE TABLE `policyDecisions` (
	`id` varchar(64) NOT NULL,
	`tenantId` varchar(64) NOT NULL,
	`requestHash` varchar(64) NOT NULL,
	`principal` varchar(160) NOT NULL,
	`toolName` varchar(160) NOT NULL,
	`requiredScope` varchar(160) NOT NULL,
	`grantedScopes` text NOT NULL,
	`decision` enum('allow','deny') NOT NULL,
	`reason` text NOT NULL,
	`source` enum('local','opa') NOT NULL DEFAULT 'local',
	`requireHumanApproval` boolean NOT NULL DEFAULT false,
	`redactions` text NOT NULL,
	`correlationId` varchar(96) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `policyDecisions_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `tenants` (
	`id` varchar(64) NOT NULL,
	`slug` varchar(64) NOT NULL,
	`name` varchar(160) NOT NULL,
	`region` varchar(64) NOT NULL,
	`status` enum('active','suspended') NOT NULL DEFAULT 'active',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `tenants_id` PRIMARY KEY(`id`),
	CONSTRAINT `tenants_slug_unique` UNIQUE(`slug`)
);
--> statement-breakpoint
CREATE INDEX `approvalRequests_tenant_idx` ON `approvalRequests` (`tenantId`);--> statement-breakpoint
CREATE INDEX `approvalRequests_status_idx` ON `approvalRequests` (`status`);--> statement-breakpoint
CREATE INDEX `approvalRequests_hash_idx` ON `approvalRequests` (`requestHash`);--> statement-breakpoint
CREATE INDEX `auditEvents_tenant_created_idx` ON `auditEvents` (`tenantId`,`createdAt`);--> statement-breakpoint
CREATE INDEX `mcpServers_tenant_idx` ON `mcpServers` (`tenantId`);--> statement-breakpoint
CREATE INDEX `mcpTools_server_idx` ON `mcpTools` (`serverId`);--> statement-breakpoint
CREATE INDEX `mcpTools_tenant_idx` ON `mcpTools` (`tenantId`);--> statement-breakpoint
CREATE INDEX `policyDecisions_tenant_idx` ON `policyDecisions` (`tenantId`);--> statement-breakpoint
CREATE INDEX `policyDecisions_correlation_idx` ON `policyDecisions` (`correlationId`);