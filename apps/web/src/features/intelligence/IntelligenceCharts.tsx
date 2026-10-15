import {
  Bar,
  BarChart,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Link, useNavigate } from 'react-router-dom';
import type { Finding, AnalysisRun } from '@proofpatch/shared';
import {
  categoryLabels,
  durationMs,
  findingState,
  findingStateLabels,
  normalizeCategory,
  normalizeSeverity,
  severityOrder,
  type RunBundle,
} from '../../lib/security-data';
import { date } from '../../components/ui';

const categoryColors = [
  '#D7FF3F',
  '#81BDB4',
  '#AC9ACF',
  '#D2AD78',
  '#BC8292',
  '#819EBE',
  '#B9BCB4',
  '#6F747E',
];
const severityColors = ['#EF8585', '#E5A476', '#D0BC76', '#82B9AB', '#969BAB'];
const percent = (count: number, total: number) =>
  total ? `${((count / total) * 100).toFixed(1)}%` : '0%';
function ChartEmpty(_: { text?: string }) {
  return (
    <div className="chart-empty">
      <span className="chart-empty-ring" />
      <h3>No data yet</h3>
    </div>
  );
}
export default function IntelligenceCharts({
  findings,
  bundle,
  runs,
  base,
}: {
  findings: Finding[];
  bundle: RunBundle;
  runs: AnalysisRun[];
  base: string;
}) {
  const navigate = useNavigate();
  const categories = categoryLabels
    .map((name, index) => ({
      name,
      count: findings.filter((finding) => normalizeCategory(finding) === name).length,
      fill: categoryColors[index],
    }))
    .filter((item) => item.count > 0);
  const severities = severityOrder.map((name, index) => ({
    name,
    label: name === 'info' ? 'Informational / Unknown' : name[0].toUpperCase() + name.slice(1),
    count: findings.filter((finding) => normalizeSeverity(finding.severity) === name).length,
    fill: severityColors[index],
  }));
  const states = Object.entries(findingStateLabels).map(([key, name]) => ({
    key,
    name,
    count: findings.filter(
      (finding) => findingState(finding, bundle.patches, bundle.verification) === key,
    ).length,
  }));
  const timeline = runs
    .filter((run) => ['failed', 'needs_review', 'verified'].includes(run.status))
    .flatMap((run) => {
      const elapsed = durationMs(run.createdAt, run.updatedAt);
      return elapsed === null
        ? []
        : [
            {
              name: run.id.slice(0, 8),
              seconds: elapsed / 1000,
              timestamp: run.createdAt,
              status: run.status,
            },
          ];
    })
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  const findingsLink = (key: string, value: string) =>
    `${base}/findings?run=${bundle.run.id}&${key}=${encodeURIComponent(value)}`;
  return (
    <>
      <div className="intelligence-chart-grid">
        <section className="panel chart-panel">
          <div className="section-header">
            <div>
              <h2>Category distribution</h2>
            </div>
            <span className="count">{findings.length} findings</span>
          </div>
          {findings.length ? (
            <>
              <div className="donut-and-legend">
                <div
                  className="donut-chart"
                  role="img"
                  aria-label={`Category distribution of ${findings.length} distinct findings`}
                >
                  <ResponsiveContainer width="100%" height="100%" minWidth={0}>
                    <PieChart>
                      <Pie
                        data={categories}
                        dataKey="count"
                        nameKey="name"
                        innerRadius="62%"
                        outerRadius="90%"
                        paddingAngle={3}
                        stroke="none"
                        isAnimationActive={false}
                        onClick={(_, index) =>
                          navigate(findingsLink('category', categories[index].name))
                        }
                      >
                        {categories.map((item) => (
                          <Cell key={item.name} fill={item.fill} />
                        ))}
                      </Pie>
                      <Tooltip
                        content={({ active, payload }) =>
                          active && payload?.length ? (
                            <div className="chart-tooltip">
                              <strong>{String(payload[0].name)}</strong>
                              <span>
                                {Number(payload[0].value)} findings ·{' '}
                                {percent(Number(payload[0].value), findings.length)}
                              </span>
                            </div>
                          ) : null
                        }
                      />
                      <text x="50%" y="47%" textAnchor="middle" className="donut-total">
                        {findings.length}
                      </text>
                      <text x="50%" y="57%" textAnchor="middle" className="donut-caption">
                        FINDINGS
                      </text>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="chart-legend">
                  {categories.map((item, index) => (
                    <Link
                      key={item.name}
                      data-category-index={index}
                      to={findingsLink('category', item.name)}
                    >
                      <i style={{ background: item.fill }} />
                      <span>{item.name}</span>
                      <strong>{item.count}</strong>
                      <small>{percent(item.count, findings.length)}</small>
                    </Link>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <ChartEmpty text="Category shares appear when this analysis records vulnerability findings." />
          )}
        </section>
        <section className="panel chart-panel">
          <div className="section-header">
            <div>
              <h2>Severity distribution</h2>
            </div>
          </div>
          {findings.length ? (
            <>
              <div
                className="severity-chart"
                role="img"
                aria-label={severities.map((item) => `${item.label}: ${item.count}`).join(', ')}
              >
                <ResponsiveContainer width="100%" height="100%" minWidth={0}>
                  <BarChart
                    data={severities}
                    layout="vertical"
                    margin={{ top: 8, right: 20, left: 0, bottom: 0 }}
                    accessibilityLayer
                  >
                    <XAxis type="number" allowDecimals={false} hide />
                    <YAxis
                      dataKey="label"
                      type="category"
                      width={140}
                      tick={{ fill: '#B7B7BD', fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Bar
                      dataKey="count"
                      name="Findings"
                      barSize={15}
                      radius={[0, 3, 3, 0]}
                      isAnimationActive={false}
                    >
                      {severities.map((item) => (
                        <Cell key={item.name} fill={item.fill} />
                      ))}
                    </Bar>
                    <Tooltip
                      cursor={{ fill: '#29292D' }}
                      content={({ active, payload }) =>
                        active && payload?.length ? (
                          <div className="chart-tooltip">
                            <strong>{payload[0].payload.label}</strong>
                            <span>
                              {Number(payload[0].value)} findings ·{' '}
                              {percent(Number(payload[0].value), findings.length)}
                            </span>
                          </div>
                        ) : null
                      }
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="severity-links">
                {severities.map((item) => (
                  <Link to={findingsLink('severity', item.name)} key={item.name}>
                    <i style={{ background: item.fill }} />
                    {item.label}
                    <strong>{item.count}</strong>
                    <small>{percent(item.count, findings.length)}</small>
                  </Link>
                ))}
              </div>
            </>
          ) : (
            <ChartEmpty text="No severity values have been recorded for this analysis." />
          )}
        </section>
      </div>
      <div className="intelligence-chart-grid">
        <section className="panel chart-panel">
          <div className="section-header">
            <div>
              <h2>Finding status</h2>
            </div>
          </div>
          {findings.length ? (
            <div className="lifecycle-chart">
              {states.map((item) => (
                <Link key={item.key} to={findingsLink('status', item.key)}>
                  <div>
                    <span>{item.name}</span>
                    <strong>
                      {item.count}
                      <small>{percent(item.count, findings.length)}</small>
                    </strong>
                  </div>
                  <span className="lifecycle-track">
                    <i style={{ width: `${(item.count / findings.length) * 100}%` }} />
                  </span>
                </Link>
              ))}
            </div>
          ) : (
            <ChartEmpty text="A proposed patch and a verified result are tracked as separate states." />
          )}
        </section>
        <section className="panel chart-panel">
          <div className="section-header">
            <div>
              <h2>Analysis elapsed time</h2>
            </div>
          </div>
          {timeline.length > 1 ? (
            <>
              <div
                className="history-chart"
                role="img"
                aria-label={`Elapsed time for ${timeline.length} settled analysis runs`}
              >
                <ResponsiveContainer width="100%" height="100%" minWidth={0}>
                  <LineChart
                    data={timeline}
                    margin={{ top: 15, right: 20, left: 0, bottom: 0 }}
                    accessibilityLayer
                  >
                    <XAxis
                      dataKey="name"
                      axisLine={false}
                      tickLine={false}
                      tick={{ fill: '#A4A4AA', fontSize: 10 }}
                    />
                    <YAxis
                      unit="s"
                      axisLine={false}
                      tickLine={false}
                      tick={{ fill: '#A4A4AA', fontSize: 10 }}
                      width={45}
                    />
                    <Line
                      type="linear"
                      dataKey="seconds"
                      name="Elapsed seconds"
                      stroke="#D7FF3F"
                      strokeWidth={2}
                      dot={{ r: 4, fill: '#D7FF3F' }}
                      isAnimationActive={false}
                    />
                    <Tooltip
                      content={({ active, payload }) =>
                        active && payload?.length ? (
                          <div className="chart-tooltip">
                            <strong>Run {payload[0].payload.name}</strong>
                            <span>{date(payload[0].payload.timestamp)}</span>
                            <span>
                              {Number(payload[0].value).toFixed(1)} seconds ·{' '}
                              {payload[0].payload.status.replaceAll('_', ' ')}
                            </span>
                          </div>
                        ) : null
                      }
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </>
          ) : (
            <div className="chart-empty">
              <h3>{timeline.length ? 'One recorded analysis' : 'No settled analysis runs'}</h3>
              <p>
                At least two timestamped runs are needed to compare elapsed times. No historical
                trend has been inferred.
              </p>
            </div>
          )}
        </section>
      </div>
    </>
  );
}
