// How a ForgejoTeam's access resolves: who (memberRefs), how much
// (permission + unitsMap), where (includesAllRepositories or the
// repository's teamRefs).

import { box, captionClass, code, dim, figureClass, frame, grant, ink, wire } from './diagram-style';

function Label({ x, y, children }: { x: number; y: number; children: string }) {
  return (
    <text x={x} y={y} style={{ ...dim, fontSize: 12, fontWeight: 600, letterSpacing: '0.14em' }}>
      {children}
    </text>
  );
}

function User({ y, name }: { y: number; name: string }) {
  return (
    <g>
      <rect x={20} y={y} width={150} height={40} style={box} />
      <text x={34} y={y + 17} style={{ ...dim, fontSize: 11 }}>ForgejoUser</text>
      <text x={34} y={y + 32} style={{ ...ink, fontSize: 13 }}>{name}</text>
    </g>
  );
}

function Unit({ y, unit, level }: { y: number; unit: string; level: string }) {
  return (
    <g>
      <text x={270} y={y} style={{ ...ink, fontSize: 13 }}>{unit}</text>
      <text x={470} y={y} textAnchor="end" style={{ ...code, fontSize: 13 }}>{level}</text>
    </g>
  );
}

function Repo({ y, name, note, granted }: { y: number; name: string; note: string; granted: boolean }) {
  return (
    <g>
      <rect
        x={580}
        y={y}
        width={182}
        height={48}
        style={{ ...box, stroke: granted ? 'var(--accent)' : 'var(--rule-soft)' }}
      />
      <text x={594} y={y + 19} style={{ ...ink, fontSize: 13 }}>{name}</text>
      <text x={594} y={y + 36} style={{ ...dim, fontSize: 11 }}>{note}</text>
    </g>
  );
}

export function TeamAccessDiagram() {
  return (
    <figure className={figureClass}>
      <svg
        viewBox="0 0 780 400"
        role="img"
        aria-labelledby="team-access-title team-access-desc"
        style={{ minWidth: 640, width: '100%', fontFamily: 'var(--face-text)' }}
      >
        <title id="team-access-title">How a ForgejoTeam grants access</title>
        <desc id="team-access-desc">
          Users listed in memberRefs belong to a team of one organization. The team&apos;s permission
          and unitsMap set the access level per repository unit. The team reaches repositories
          either through includesAllRepositories or through each repository&apos;s teamRefs.
        </desc>
        <defs>
          <marker id="team-access-arrow" viewBox="0 0 8 8" refX={7} refY={4} markerWidth={8} markerHeight={8} orient="auto">
            <path d="M0,0 L8,4 L0,8 z" style={{ fill: 'var(--ink-dim)' }} />
          </marker>
          <marker id="team-access-grant" viewBox="0 0 8 8" refX={7} refY={4} markerWidth={8} markerHeight={8} orient="auto">
            <path d="M0,0 L8,4 L0,8 z" style={{ fill: 'var(--accent)' }} />
          </marker>
        </defs>

        <Label x={20} y={28}>WHO</Label>
        <Label x={240} y={28}>HOW MUCH</Label>
        <Label x={580} y={28}>WHERE</Label>

        {/* Who: memberRefs */}
        <User y={110} name="alice" />
        <User y={170} name="carol" />
        <path d="M170,130 L238,170" style={wire} markerEnd="url(#team-access-arrow)" />
        <path d="M170,190 L238,190" style={wire} markerEnd="url(#team-access-arrow)" />
        <text x={20} y={240} style={{ ...dim, fontSize: 11 }}>spec.memberRefs</text>
        <text x={20} y={256} style={{ ...dim, fontSize: 11 }}>(authoritative)</text>

        {/* How much: the team, inside its organization */}
        <rect x={220} y={44} width={300} height={340} style={frame} />
        <text x={232} y={64} style={{ ...dim, fontSize: 11 }}>ForgejoOrganization weebo</text>

        <rect x={240} y={78} width={260} height={290} style={box} />
        <text x={256} y={100} style={{ ...dim, fontSize: 11 }}>ForgejoTeam</text>
        <text x={256} y={118} style={{ ...ink, fontSize: 14, fontWeight: 600 }}>devs</text>

        <line x1={256} y1={132} x2={484} y2={132} style={{ stroke: 'var(--rule-soft)' }} />
        <text x={256} y={154} style={{ ...ink, fontSize: 13 }}>permission</text>
        <text x={470} y={154} textAnchor="end" style={{ ...code, fontSize: 13 }}>read</text>
        <text x={256} y={172} style={{ ...dim, fontSize: 11 }}>read · write · admin</text>

        <line x1={256} y1={186} x2={484} y2={186} style={{ stroke: 'var(--rule-soft)' }} />
        <text x={256} y={206} style={{ ...ink, fontSize: 13 }}>unitsMap</text>
        <Unit y={228} unit="repo.code" level="read" />
        <Unit y={248} unit="repo.issues" level="write" />
        <Unit y={268} unit="repo.pulls" level="write" />
        <Unit y={288} unit="repo.actions" level="none" />
        <text x={256} y={312} style={{ ...dim, fontSize: 11 }}>none · read · write · admin</text>
        <text x={256} y={328} style={{ ...dim, fontSize: 11 }}>empty: every unit at permission</text>
        <text x={256} y={344} style={{ ...dim, fontSize: 11 }}>ignored when permission is admin</text>

        {/* Where: the repositories the team reaches */}
        <Repo y={78} name="app" note="teamRefs: [weebo-devs]" granted />
        <Repo y={150} name="docs" note="teamRefs: [weebo-devs]" granted />
        <Repo y={222} name="infra" note="not listed: no access" granted={false} />
        <path d="M500,120 L578,102" style={grant} markerEnd="url(#team-access-grant)" />
        <path d="M500,165 L578,174" style={grant} markerEnd="url(#team-access-grant)" />

        <rect x={580} y={300} width={182} height={68} style={frame} />
        <text x={594} y={322} style={{ ...ink, fontSize: 13 }}>includesAll-</text>
        <text x={594} y={338} style={{ ...ink, fontSize: 13 }}>Repositories: true</text>
        <text x={594} y={356} style={{ ...dim, fontSize: 11 }}>every repo, even future</text>
        <path d="M500,334 L578,334" style={{ ...wire, strokeDasharray: '4 3' }} markerEnd="url(#team-access-arrow)" />
      </svg>
      <figcaption className={captionClass}>
        The team sets the level, the repository decides whether the team gets in.
      </figcaption>
    </figure>
  );
}
