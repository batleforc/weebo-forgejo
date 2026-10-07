// Guided choices for the manifest builder, in the spirit of batlehub's config
// generator: several kinds accept mutually exclusive ways of doing one thing
// (a repository is created empty, from a template, or by migrating). The
// schema can only say "these are all optional"; this file says which go
// together, so the form asks "how?" first and shows only the matching fields.
//
// Field names are `spec` keys. A kind not listed here gets the plain form.

import type { FieldSchema } from "./types";

export interface ChoiceOption {
  id: string;
  label: string;
  /** One line under the segmented control, shown while this option is chosen. */
  hint: string;
  /** Spec fields shown (and kept in the manifest) only for this option. */
  fields: string[];
  /** Of those, the ones this option can't do without (marked required). */
  require?: string[];
  /** Spec values this option implies; their fields are never shown. */
  set?: Record<string, unknown>;
}

export interface ChoiceGroup {
  id: string;
  label: string;
  options: ChoiceOption[];
}

export const CHOICES: Record<string, ChoiceGroup[]> = {
  ForgejoRepository: [
    {
      id: "owner",
      label: "Owned by",
      options: [
        { id: "org", label: "Organization", hint: "The usual case: the repository lives in an organization.", fields: ["organizationRef", "teamRefs"], require: ["organizationRef"] },
        { id: "user", label: "User", hint: "A personal repository of a ForgejoUser.", fields: ["userRef"], require: ["userRef"] },
      ],
    },
    {
      id: "source",
      label: "Start from",
      options: [
        { id: "init", label: "Empty", hint: "A new repository, optionally with a README, license and .gitignore.", fields: ["init"] },
        { id: "template", label: "Template", hint: "Generated from a template ForgejoRepository in the same namespace.", fields: ["fromTemplate"], require: ["fromTemplate"] },
        { id: "migrate", label: "Mirror / migrate", hint: "Cloned from a remote, once or as a pull mirror.", fields: ["migrate"], require: ["migrate"] },
      ],
    },
  ],
  ForgejoWebhook: [
    {
      id: "target",
      label: "Attach to",
      options: [
        { id: "repo", label: "Repository", hint: "Fires for one repository in the same namespace.", fields: ["repositoryRef"], require: ["repositoryRef"] },
        { id: "org", label: "Organization", hint: "Fires for every repository of an organization.", fields: ["organizationRef"], require: ["organizationRef"] },
      ],
    },
  ],
  ForgejoUser: [
    {
      id: "account",
      label: "Account",
      options: [
        {
          id: "local",
          label: "Local",
          hint: "Signs in with a password the operator generates into secretTargets.",
          fields: ["secretTargets", "mustChangePassword"],
          require: ["secretTargets"],
        },
        {
          id: "sso",
          label: "SSO",
          hint: "Signs in through an OIDC/LDAP source; Forgejo links the account at first sign-in.",
          fields: ["loginSourceId", "loginName"],
          require: ["loginSourceId"],
        },
        {
          id: "bot",
          label: "Bot",
          hint: "No usable password: works only through its access tokens and SSH keys.",
          fields: [],
          set: { bot: true },
        },
      ],
    },
    {
      id: "policy",
      label: "Managed",
      options: [
        { id: "manage", label: "Create & manage", hint: "The operator creates the account and keeps it in line with this spec.", fields: [] },
        {
          id: "observe",
          label: "Observe only",
          hint: "Never created or changed: only looked up so teams and tokens can refer to it.",
          fields: [],
          set: { managementPolicy: "Observe" },
        },
      ],
    },
  ],
  ForgejoDeployKey: [
    {
      id: "key",
      label: "Key",
      options: [
        { id: "generate", label: "Generate", hint: "An ed25519 pair is generated; the private key goes to secretTargets.", fields: ["secretTargets"] },
        { id: "own", label: "Bring your own", hint: "Register a public key you already have.", fields: ["publicKey"], require: ["publicKey"] },
      ],
    },
  ],
  ForgejoUserKey: [
    {
      id: "key",
      label: "Key",
      options: [
        { id: "generate", label: "Generate", hint: "An ed25519 pair is generated; the private key goes to secretTargets.", fields: ["secretTargets"] },
        { id: "own", label: "Bring your own", hint: "Register a public key you already have.", fields: ["publicKey"], require: ["publicKey"] },
      ],
    },
  ],
  ForgejoOAuth2Application: [
    {
      id: "owner",
      label: "Owned by",
      options: [
        { id: "admin", label: "Operator's admin", hint: "The default: the application belongs to the admin account the operator uses.", fields: [] },
        { id: "user", label: "A user", hint: "Keep applications off the admin's profile, e.g. on a dedicated bot.", fields: ["ownerRef"], require: ["ownerRef"] },
      ],
    },
  ],
  ForgejoAccessToken: [
    {
      id: "scope",
      label: "Repositories",
      options: [
        { id: "all", label: "All", hint: "The token works on every repository the user can reach.", fields: [] },
        {
          id: "some",
          label: "Only some",
          hint: "Restricted to the listed repositories; only issue/repository scopes are allowed.",
          fields: ["repositoryRefs"],
          require: ["repositoryRefs"],
        },
      ],
    },
  ],
};

export type Selection = Record<string, string>;

export function defaultSelection(groups: ChoiceGroup[]): Selection {
  return Object.fromEntries(groups.map((g) => [g.id, g.options[0].id]));
}

function chosen(groups: ChoiceGroup[], selection: Selection): ChoiceOption[] {
  return groups.map((g) => g.options.find((o) => o.id === selection[g.id]) ?? g.options[0]);
}

/** Spec keys the form must not render: other options' fields, and implied values. */
export function hiddenKeys(groups: ChoiceGroup[], selection: Selection): string[] {
  const picked = chosen(groups, selection);
  const shown = new Set(picked.flatMap((o) => o.fields));
  const hidden = new Set<string>();
  for (const group of groups) {
    for (const option of group.options) {
      for (const key of option.fields) if (!shown.has(key)) hidden.add(key);
      for (const key of Object.keys(option.set ?? {})) hidden.add(key);
    }
  }
  return [...hidden];
}

/** The spec as the manifest should carry it: hidden fields dropped, implied values set. */
export function applySelection(
  groups: ChoiceGroup[],
  selection: Selection,
  spec: Record<string, unknown>,
): Record<string, unknown> {
  const out = { ...spec };
  for (const key of hiddenKeys(groups, selection)) delete out[key];
  for (const option of chosen(groups, selection)) Object.assign(out, option.set ?? {});
  return out;
}

/** The schema with the chosen options' must-have fields marked required. */
export function withChoiceRequirements<S extends FieldSchema>(
  groups: ChoiceGroup[],
  selection: Selection,
  schema: S,
): S {
  const extra = chosen(groups, selection).flatMap((o) => o.require ?? []);
  if (extra.length === 0) return schema;
  return { ...schema, required: [...new Set([...(schema.required ?? []), ...extra])] };
}

/** The spec fields the chosen options are about, shown before the rest. */
export function chosenFields(groups: ChoiceGroup[], selection: Selection): string[] {
  return chosen(groups, selection).flatMap((o) => o.fields);
}
