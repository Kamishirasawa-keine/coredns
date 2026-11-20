'use strict';
'require view';
'require rpc';
'require poll';
'require dom';

const getMetrics = rpc.declare({
	object: 'luci.coredns',
	method: 'get_metrics',
	reject: true
});

const totals = {
	coredns_dns_requests_total: 'requests',
	coredns_cache_hits_total: 'hits',
	coredns_cache_requests_total: 'cacheRequests'
};

const upstreamFields = {
	coredns_splitroute_upstream_requests_total: 'requests',
	coredns_splitroute_upstream_failures_total: 'failures',
	coredns_splitroute_upstream_duration_seconds_sum: 'duration',
	coredns_splitroute_upstream_duration_seconds_count: 'timed'
};

function parseMetrics(text) {
	const summary = { requests: 0, hits: 0, cacheRequests: 0 };
	let blockCount = null;
	let blockDomainCount = null;
	const upstreams = new Map();
	for (const line of text.split('\n')) {
		const sample = line.match(/^(coredns_\w+)(?:\{(.*)\})?\s+(\S+)/);
		if (!sample)
			continue;

		const [, name, labels, value] = sample;
		const count = Number(value);
		if (!Number.isFinite(count) || count < 0)
			continue;
		if (Object.hasOwn(totals, name)) {
			summary[totals[name]] += count;
			continue;
		}

		if (name === 'coredns_blocklist_block_count_total') {
			blockCount = (blockCount ?? 0) + count;
			continue;
		}
		if (name === 'coredns_blocklist_block_count_with_domains_total') {
			blockDomainCount = (blockDomainCount ?? 0) + count;
			continue;
		}
		const field = upstreamFields[name];
		if (!field)
			continue;
		const label = {};
		for (const match of (labels ?? '').matchAll(/(group|upstream)="((?:[^"\\]|\\.)*)"/g))
			label[match[1]] = match[2].replace(/\\([\\"n])/g, (_, c) => c === 'n' ? '\n' : c);
		if (!label.group || !label.upstream)
			continue;
		const key = JSON.stringify([ label.group, label.upstream ]);
		const row = upstreams.get(key) ?? { group: label.group, upstream: label.upstream, requests: 0, failures: 0, duration: 0, timed: 0 };
		row[field] += count;
		upstreams.set(key, row);
	}
	return { ...summary, blocked: blockCount ?? blockDomainCount, upstreams: Array.from(upstreams.values()).sort((a, b) =>
		a.group.localeCompare(b.group) || a.upstream.localeCompare(b.upstream)) };
}

function percent(count, total) {
	return total ? (100 * count / total).toLocaleString(undefined, { maximumFractionDigits: 2 }) + '%' : '—';
}

function table(title, headers, rows) {
	return [
		E('h3', {}, [ title ]),
		E('table', { class: 'table' }, [
			E('tr', { class: 'tr table-titles' }, headers.map(text => E('th', { class: 'th' }, [ text ]))),
			...rows.map(row => E('tr', { class: 'tr' }, row.map(value => E('td', { class: 'td' }, [ value ]))))
		])
	];
}

return view.extend({
	render() {
		const stats = E('div', {}, [ _('Collecting data ...') ]);
		poll.add(async () => {
			const result = await getMetrics().catch(() => null);
			if (result?.error === 'size') {
				dom.content(stats, [ _('The Prometheus response exceeds the statistics page limit.') ]);
				return;
			}
			if (typeof result?.content !== 'string' || !/^coredns_build_info\{/m.test(result.content)) {
				dom.content(stats, [ _('CoreDNS statistics are unavailable. Check that CoreDNS is running and the Corefile contains “prometheus 127.0.0.1:9153”.') ]);
				return;
			}
			const m = parseMetrics(result.content);
			dom.content(stats, [
				...table(_('DNS overview'), [ _('Metric'), _('Value') ], [
					[ _('DNS requests'), m.requests.toLocaleString() ],
					[ _('Cache hits'), m.hits.toLocaleString() ],
					[ _('Cache hit rate'), percent(m.hits, m.cacheRequests) ],
					[ _('Blocked requests'), m.blocked?.toLocaleString() ?? '—' ],
					[ _('Block rate'), m.blocked == null ? '—' : percent(m.blocked, m.requests) ]
				]),
				...(m.blocked == null ? [ E('p', {}, [ _('Prometheus has not reported a blocklist counter. Query a known blocked domain directly on this CoreDNS instance (bypassing the client cache), then check again.') ]) ] : []),
				...table(_('Upstreams'), [ _('Group'), _('Upstream'), _('Requests'), _('Failures'), _('Average latency') ],
					m.upstreams.map(row => [ row.group, row.upstream, row.requests.toLocaleString(), row.failures.toLocaleString(),
						row.timed ? (1000 * row.duration / row.timed).toLocaleString(undefined, { maximumFractionDigits: 2 }) + ' ms' : '—' ])),
				...(m.upstreams.length ? [] : [ E('p', {}, [ _('No per-upstream counters are available.') ]) ])
			]);
		}, 5);

		return E('div', {}, [
			E('h2', {}, [ _('CoreDNS statistics') ]),
			E('p', {}, [ _('Counters are cumulative since CoreDNS started. One DNS request can contact multiple upstreams.') ]),
			stats
		]);
	},
	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
