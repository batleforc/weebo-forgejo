// How an OIDC group becomes a team membership: the group at the provider,
// the `groups` claim at sign-in, the auth source's dyn-group-maps pattern,
// the team — and, below, the two operators that declare the group and the
// team but never the membership itself.

import { box, captionClass, code, dim, figureClass, frame, grant, ink, wire } from '@weebo/operator-docs/diagram-style';

const COLS = [20, 232, 444, 656];
const W = 185;

function Lane({ x, children }: { x: number; children: string }) {
  return (
    <text x={x} y={28} style={{ ...dim, fontSize: 12, fontWeight: 600, letterSpacing: '0.14em' }}>
      {children}
    </text>
  );
}

function Stage({
  x,
  kind,
  title,
  label,
  value,
  lit = false,
}: {
  x: number;
  kind: string;
  title: string;
  label: string;
  value: string;
  lit?: boolean;
}) {
  return (
    <g>
      <rect x={x} y={44} width={W} height={112} style={lit ? { ...box, stroke: 'var(--accent)' } : box} />
      <text x={x + 14} y={66} style={{ ...dim, fontSize: 11 }}>{kind}</text>
      <text x={x + 14} y={86} style={{ ...ink, fontSize: 13, fontWeight: 600 }}>{title}</text>
      <line x1={x + 14} y1={100} x2={x + W - 14} y2={100} style={{ stroke: 'var(--rule-soft)' }} />
      <text x={x + 14} y={120} style={{ ...dim, fontSize: 11 }}>{label}</text>
      <text x={x + 14} y={140} style={{ ...code, fontSize: 12 }}>{value}</text>
    </g>
  );
}

function Declares({ x, who, kind, field }: { x: number; who: string; kind: string; field: string }) {
  return (
    <g>
      <rect x={x} y={244} width={210} height={74} style={box} />
      <text x={x + 14} y={264} style={{ ...dim, fontSize: 11 }}>{who}</text>
      <text x={x + 14} y={284} style={{ ...ink, fontSize: 13 }}>{kind}</text>
      <text x={x + 14} y={304} style={{ ...code, fontSize: 12 }}>{field}</text>
    </g>
  );
}

export function GroupSyncDiagram() {
  return (
    <figure className={figureClass}>
      <svg
        viewBox="0 0 860 340"
        role="img"
        aria-labelledby="group-sync-title group-sync-desc"
        style={{ minWidth: 700, width: '100%', fontFamily: 'var(--face-text)' }}
      >
        <title id="group-sync-title">How an OIDC group fills a Forgejo team</title>
        <desc id="group-sync-desc">
          Alice is in the Authentik group forgejo/weebo/devs. When she signs in to Forgejo, the ID
          token carries that group in its groups claim. The authentication source matches it against
          the pattern forgejo/org/team and adds her to the team devs of the organization weebo. In
          Kubernetes, weebo-authentik declares the group and weebo-forgejo declares the team with
          membersPolicy External; neither writes the membership.
        </desc>
        <defs>
          <marker id="group-sync-arrow" viewBox="0 0 8 8" refX={7} refY={4} markerWidth={8} markerHeight={8} orient="auto">
            <path d="M0,0 L8,4 L0,8 z" style={{ fill: 'var(--ink-dim)' }} />
          </marker>
          <marker id="group-sync-grant" viewBox="0 0 8 8" refX={7} refY={4} markerWidth={8} markerHeight={8} orient="auto">
            <path d="M0,0 L8,4 L0,8 z" style={{ fill: 'var(--accent)' }} />
          </marker>
        </defs>

        <Lane x={COLS[0]}>PROVIDER</Lane>
        <Lane x={COLS[1]}>SIGN-IN</Lane>
        <Lane x={COLS[2]}>AUTH SOURCE</Lane>
        <Lane x={COLS[3]}>TEAM</Lane>

        <Stage x={COLS[0]} kind="Authentik group" title="forgejo/weebo/devs" label="members" value="alice" />
        <Stage x={COLS[1]} kind="ID token of alice" title="claim groups" label="contains" value="forgejo/weebo/devs" />
        <Stage x={COLS[2]} kind="dynGroupMaps" title="forgejo/{org}/{team}" label="matches" value="org weebo, team devs" />
        <Stage x={COLS[3]} kind="Forgejo team" title="weebo / devs" label="members" value="alice" lit />

        <path d={`M${COLS[0] + W},100 L${COLS[1] - 2},100`} style={wire} markerEnd="url(#group-sync-arrow)" />
        <path d={`M${COLS[1] + W},100 L${COLS[2] - 2},100`} style={wire} markerEnd="url(#group-sync-arrow)" />
        <path d={`M${COLS[2] + W},100 L${COLS[3] - 2},100`} style={grant} markerEnd="url(#group-sync-grant)" />

        {/* Kubernetes: what the operators declare */}
        <rect x={20} y={196} width={820} height={136} style={frame} />
        <text x={34} y={220} style={{ ...dim, fontSize: 12, fontWeight: 600, letterSpacing: '0.14em' }}>
          KUBERNETES
        </text>
        <Declares x={34} who="weebo-authentik" kind="AuthentikGroup" field="+ AuthentikUser.groupRefs" />
        <Declares x={616} who="weebo-forgejo" kind="ForgejoTeam devs" field="membersPolicy: External" />
        <path d="M190,244 L190,158" style={{ ...wire, strokeDasharray: '4 3' }} markerEnd="url(#group-sync-arrow)" />
        <path d="M760,244 L760,158" style={{ ...wire, strokeDasharray: '4 3' }} markerEnd="url(#group-sync-arrow)" />
        <text x={598} y={274} textAnchor="end" style={{ ...dim, fontSize: 11 }}>
          creates the team, its rights and repositories;
        </text>
        <text x={598} y={290} textAnchor="end" style={{ ...dim, fontSize: 11 }}>
          never adds or removes its members
        </text>
      </svg>
      <figcaption className={captionClass}>
        At each sign-in, Forgejo matches the groups claim against the pattern and adds or removes the
        user. The operators declare the group and the team, never the membership.
      </figcaption>
    </figure>
  );
}
