/**
 * Decimal text in the inclusive u64 range, with no sign or leading zero
 * unless the complete component is exactly "0".
 */
export type DecimalU64 = string;

/** Exactly three canonical decimal u64 components separated by dots. */
export type StableVersion = `${DecimalU64}.${DecimalU64}.${DecimalU64}`;

/** The closed provisioning-request.v1 data shape. */
export interface ProvisioningRequestV1 {
  readonly action: "provision";
  readonly release: {
    readonly channel: "stable";
    readonly target: "linux-amd64";
    readonly version: StableVersion;
  };
  readonly request_id: string;
  readonly schema_version: 1;
}

/** The closed inert systemd-hardening.v1 data shape. */
export interface SystemdHardeningV1 {
  readonly AmbientCapabilities: readonly [];
  readonly CapabilityBoundingSet: readonly [];
  readonly NoNewPrivileges: "yes";
  readonly PrivateTmp: "yes";
  readonly ProtectHome: "yes";
  readonly ProtectSystem: "strict";
  readonly RestrictAddressFamilies: readonly ["AF_UNIX"];
  readonly RestrictSUIDSGID: "yes";
  readonly schema_version: 1;
}

